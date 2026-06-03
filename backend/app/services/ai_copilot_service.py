from datetime import datetime, timedelta, timezone
import re
from typing import Any

from fastapi import HTTPException

from app.common.mongo import parse_object_id, serialize_document
from app.db.client import (
    alerts_collection,
    incidents_collection,
    response_actions_collection,
    security_blocks_collection,
)
from app.services.threat_intel_service import get_feed, lookup_ioc

SEVERITY_WEIGHTS = {
    "informational": 5,
    "info": 5,
    "low": 10,
    "medium": 25,
    "high": 45,
    "critical": 65,
}

ACTION_VALUES = {
    "block_ip",
    "isolate_host",
    "escalate_to_admin",
    "monitor_only",
    "close_false_positive",
    "open_investigation",
    "run_threat_hunt",
}


async def triage_alert(alert_id: str, organization_id: str) -> dict:
    alert = await _get_alert(alert_id, organization_id)
    related_alerts = await _related_alerts(alert, organization_id)
    risk_score, reasoning = await _alert_risk(alert, related_alerts, organization_id)
    priority = _priority_for_score(risk_score)
    return {
        "alert_id": str(alert.get("_id") or alert_id),
        "risk_score": risk_score,
        "priority": priority,
        "reasoning": reasoning,
        "recommended_action": _recommended_action_for_alert(alert, risk_score),
        "mapped_mitre_techniques": _mitre_from_alerts([alert]),
    }


async def score_false_positive(alert_id: str, organization_id: str) -> dict:
    alert = await _get_alert(alert_id, organization_id)
    related_alerts = await _related_alerts(alert, organization_id)
    risk_score, _ = await _alert_risk(alert, related_alerts, organization_id)
    score = 50
    reasons = []

    if risk_score >= 80:
        score -= 35
        reasons.append("High deterministic risk score makes a false positive less likely.")
    elif risk_score <= 35:
        score += 20
        reasons.append("Low deterministic risk score increases false-positive likelihood.")

    severity = _lower(alert.get("severity"))
    if severity in {"low", "informational", "info"}:
        score += 15
        reasons.append("Low severity alert is more often monitored before escalation.")
    if _confidence(alert) >= 0.8:
        score -= 20
        reasons.append("Rule or classifier confidence is high.")
    if related_alerts and len(related_alerts) >= 5:
        score -= 15
        reasons.append("Repeated matching alerts reduce false-positive likelihood.")
    if _mitre_from_alerts([alert]):
        score -= 10
        reasons.append("MITRE mapping provides meaningful adversary context.")
    if _is_failed_login(alert) and int(alert.get("failed_login_count") or 0) <= 1:
        score += 15
        reasons.append("Single failed-login events can be benign user error.")
    if _is_dos(alert):
        score -= 15
        reasons.append("DoS/DDoS indicators are present and should be investigated.")

    score = _clamp(score)
    confidence = "high" if len(reasons) >= 4 else "medium" if len(reasons) >= 2 else "low"
    suggested_status = (
        "likely_false_positive" if score >= 75 else "monitor" if score >= 50 else "investigate"
    )
    if not reasons:
        reasons.append("No strong deterministic false-positive signals were found.")
    return {
        "alert_id": str(alert.get("_id") or alert_id),
        "false_positive_score": score,
        "confidence": confidence,
        "reasons": reasons,
        "suggested_status": suggested_status,
    }


async def summarize_incident(incident_id: str, organization_id: str) -> dict:
    incident = await _get_incident_with_related_alerts(incident_id, organization_id)
    related_alerts = incident.get("related_alerts", [])
    actions = recommend_actions_for_incident_document(incident)
    affected_assets = _affected_assets(incident, related_alerts)
    timeline = _timeline(incident, related_alerts)
    title = incident.get("title") or _incident_title(incident, related_alerts)

    return {
        "incident_id": str(incident.get("_id") or incident_id),
        "title": title,
        "executive_summary": _executive_summary(incident, related_alerts, affected_assets),
        "root_cause_guess": _root_cause_guess(incident, related_alerts),
        "affected_assets": affected_assets,
        "attack_timeline": timeline,
        "mitre_techniques": _mitre_from_alerts(related_alerts) or _mitre_from_incident(incident),
        "recommended_actions": actions["recommended_actions"],
        "analyst_next_steps": _analyst_next_steps(incident, related_alerts),
    }


async def recommend_actions_for_incident(incident_id: str, organization_id: str) -> dict:
    incident = await _get_incident_with_related_alerts(incident_id, organization_id)
    result = recommend_actions_for_incident_document(incident)
    return {"incident_id": str(incident.get("_id") or incident_id), **result}


def recommend_actions_for_incident_document(incident: dict) -> dict:
    related_alerts = incident.get("related_alerts", [])
    severity = _lower(incident.get("severity"))
    text = _search_text([incident, *related_alerts])
    actions: list[str] = []
    reasons: list[str] = []

    if severity in {"critical", "high"}:
        actions.append("open_investigation")
        reasons.append("Incident severity requires analyst-owned investigation.")
    if "critical" == severity:
        actions.append("escalate_to_admin")
        reasons.append("Critical incidents should be escalated to an administrator.")
    if any(_is_dos(alert) for alert in related_alerts) or "ddos" in text or "dos" in text:
        actions.extend(["block_ip", "run_threat_hunt"])
        reasons.append("DoS/DDoS indicators suggest containment and scoping.")
    if any(_is_failed_login(alert) for alert in related_alerts) or "failed login" in text:
        actions.append("run_threat_hunt")
        reasons.append("Failed-login indicators should be scoped across users, hosts, and IPs.")
    if any(_host(alert) for alert in related_alerts) and severity in {"critical", "high"}:
        actions.append("isolate_host")
        reasons.append("High-impact host involvement may require endpoint containment.")
    if not actions:
        actions.append("monitor_only")
        reasons.append("No high-confidence containment signal was found.")
    if _lower(incident.get("status")) == "false_positive":
        actions = ["close_false_positive"]
        reasons = ["Incident is already marked as false positive."]

    return {
        "recommended_actions": _unique_actions(actions),
        "reasons": reasons,
    }


async def interpret_soc_query(query: str, organization_id: str) -> dict:
    normalized = " ".join(query.lower().split())
    filters: dict[str, Any] = {}
    endpoint = "/alerts/"
    intent = "unknown"
    explanation = "Parsed as a general SOC search."
    preview = None

    if "blocked ip" in normalized or "blocked ips" in normalized:
        intent = "show_blocked_ips"
        endpoint = "/soar/blocked-ips"
        explanation = "The query asks for response actions that blocked source IPs."
        preview = await _blocked_ips_preview(organization_id)
    elif "threat feed" in normalized or "malicious indicators" in normalized:
        intent = "threat_feed"
        filters = {"verdict": "malicious"} if "malicious indicators" in normalized else {}
        endpoint = "/api/threat-intel/feed"
        explanation = "Showing deterministic internal threat intelligence feed."
        feed_items = get_feed()["items"]
        if filters.get("verdict"):
            feed_items = [item for item in feed_items if item.get("verdict") == filters["verdict"]]
        preview = {"count": len(feed_items), "sample": feed_items[:5]}
    elif threat_indicator := _threat_lookup_indicator(normalized):
        intent = "threat_lookup"
        filters = {"indicator": threat_indicator}
        endpoint = f"/api/threat-intel/lookup?indicator={threat_indicator}"
        explanation = f"Looking up threat intelligence for {threat_indicator}."
        preview = lookup_ioc(threat_indicator)
    elif "incident" in normalized:
        intent = "show_incidents"
        endpoint = "/incidents/"
        if "last 24 hour" in normalized or "past 24 hour" in normalized:
            filters["from"] = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            explanation = "The query asks for incidents opened in the last 24 hours."
        else:
            explanation = "The query asks for incidents matching the available incident filters."
        if "dos" in normalized or "ddos" in normalized:
            filters["event_type"] = "dos_ddos"
            explanation = "The query asks for DoS or DDoS incidents."
        preview = await _preview_incidents(organization_id, filters)
    elif "failed login" in normalized or "failed logins" in normalized:
        intent = "show_failed_logins"
        filters = {"event_type": "failed_login"}
        endpoint = "/alerts/?event_type=failed_login"
        explanation = "The query asks for alerts with failed-login indicators."
        preview = await _preview_alerts(organization_id, filters)
    elif severity := _severity_alert_query(normalized):
        intent = "alert_search"
        filters = {"severity": severity}
        endpoint = f"/api/alerts?severity={severity}"
        explanation = f"Showing {severity} severity alerts."
        preview = await _preview_alerts(organization_id, filters)
    elif "dos" in normalized or "ddos" in normalized:
        intent = "show_dos_attacks"
        filters = {"event_type": "dos_ddos"}
        endpoint = "/alerts/?event_type=dos_ddos"
        explanation = "The query asks for DoS or DDoS attack activity."
        preview = await _preview_alerts(organization_id, filters)
    else:
        mitre = re.search(r"\b(t\d{4}(?:\.\d{3})?)\b", normalized, re.IGNORECASE)
        host = re.search(r"\bhost\s+([a-z0-9_.-]+)\b", normalized, re.IGNORECASE)
        if mitre:
            technique = mitre.group(1).upper()
            intent = "show_mitre_activity"
            filters = {"mitre_technique_id": technique}
            endpoint = f"/alerts/?mitre_technique_id={technique}"
            explanation = f"The query asks for activity mapped to MITRE technique {technique}."
            preview = await _preview_alerts(organization_id, filters)
        elif host:
            host_value = host.group(1)
            intent = "show_alerts_for_host"
            filters = {"host": host_value}
            endpoint = f"/alerts/?host={host_value}"
            explanation = f"The query asks for alerts involving host {host_value}."
            preview = await _preview_alerts(organization_id, filters)

    return {
        "intent": intent,
        "filters": filters,
        "backend_endpoint_suggestion": endpoint,
        "explanation": explanation,
        "result_preview": preview,
    }


async def _get_alert(alert_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(alert_id, "alert")
    alert = await alerts_collection.find_one({"_id": object_id, "organization_id": organization_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return serialize_document(alert)


async def _get_incident_with_related_alerts(incident_id: str, organization_id: str) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    incident = await incidents_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    serialized = serialize_document(incident)
    existing_alerts = [
        serialize_document(alert) if isinstance(alert, dict) else alert
        for alert in serialized.get("related_alerts", [])
        if isinstance(alert, dict)
    ]
    alert_ids = [str(serialized["alert_id"])] if serialized.get("alert_id") else []
    alert_ids.extend(str(alert_id) for alert_id in serialized.get("related_alert_ids", []))
    existing_ids = {str(alert.get("_id") or alert.get("id")) for alert in existing_alerts}
    wanted = {alert_id for alert_id in alert_ids if alert_id not in existing_ids}
    if wanted:
        cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
        async for alert in cursor:
            item = serialize_document(alert)
            if str(item.get("_id") or item.get("id")) in wanted:
                existing_alerts.append(item)
    serialized["related_alerts"] = existing_alerts
    return serialized


async def _related_alerts(alert: dict, organization_id: str) -> list[dict]:
    fields = [
        alert.get("source_ip"),
        alert.get("ip_address"),
        alert.get("hostname"),
        alert.get("host"),
        alert.get("event_type"),
        alert.get("matched_rule_id"),
    ]
    if not any(fields):
        return []
    related = []
    cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for candidate in cursor:
        item = serialize_document(candidate)
        if str(item.get("_id")) == str(alert.get("_id")):
            continue
        if _is_related(alert, item):
            related.append(item)
    return related


async def _alert_risk(alert: dict, related_alerts: list[dict], organization_id: str) -> tuple[int, list[str]]:
    score = SEVERITY_WEIGHTS.get(_lower(alert.get("severity")), 15)
    reasons = [f"Severity contributes {score} risk points."]
    confidence = _confidence(alert)
    if confidence:
        points = round(confidence * 20)
        score += points
        reasons.append(f"Rule confidence contributes {points} risk points.")
    if await _has_ip_reputation(alert, organization_id):
        score += 20
        reasons.append("Source IP has prior block or reputation context.")
    if len(related_alerts) >= 10:
        score += 20
        reasons.append("Ten or more repeated related alerts were observed.")
    elif len(related_alerts) >= 3:
        score += 10
        reasons.append("Multiple repeated related alerts were observed.")
    host_count = len({_host(item) for item in [alert, *related_alerts] if _host(item)})
    if host_count >= 3:
        score += 15
        reasons.append("Activity affects three or more hosts.")
    elif host_count >= 2:
        score += 8
        reasons.append("Activity affects multiple hosts.")
    if _mitre_from_alerts([alert]):
        score += 10
        reasons.append("MITRE ATT&CK mapping is available.")
    if _is_dos(alert):
        score += 20
        reasons.append("DoS/DDoS indicators are present.")
    if _is_failed_login(alert):
        score += 12
        reasons.append("Failed-login indicators are present.")
    return _clamp(score), reasons


async def _has_ip_reputation(alert: dict, organization_id: str) -> bool:
    ip = _ip(alert)
    if not ip:
        return False
    block = await security_blocks_collection.find_one(
        {"organization_id": organization_id, "ip_address": ip}
    )
    if block:
        return True
    action = await response_actions_collection.find_one(
        {"organization_id": organization_id, "ip_address": ip}
    )
    return bool(action)


def _confidence(alert: dict) -> float:
    raw = alert.get("rule_confidence", alert.get("confidence", alert.get("classifier_confidence")))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return 0.6 if alert.get("matched_rule_id") or alert.get("matched_rule_name") else 0
    return value / 100 if value > 1 else value


def _recommended_action_for_alert(alert: dict, risk_score: int) -> str:
    if risk_score >= 75 and _ip(alert):
        return "block_ip"
    if risk_score >= 85 and _host(alert):
        return "isolate_host"
    if risk_score >= 60:
        return "open_investigation"
    if risk_score >= 35:
        return "monitor_only"
    return "close_false_positive"


def _priority_for_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _is_related(left: dict, right: dict) -> bool:
    return any(
        [
            _ip(left) and _ip(left) == _ip(right),
            _host(left) and _host(left) == _host(right),
            left.get("event_type") and left.get("event_type") == right.get("event_type"),
            left.get("matched_rule_id") and left.get("matched_rule_id") == right.get("matched_rule_id"),
        ]
    )


def _severity_alert_query(normalized_query: str) -> str | None:
    severity_pattern = r"(critical|high|medium|low)"
    patterns = [
        rf"\b{severity_pattern}\s+severity\s+alerts?\b",
        rf"\b{severity_pattern}\s+alerts?\b",
        rf"\balerts?\s+(?:with\s+)?severity\s+{severity_pattern}\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized_query)
        if match:
            return next(group for group in match.groups() if group)
    return None


def _threat_lookup_indicator(normalized_query: str) -> str | None:
    patterns = [
        r"\bis\s+([^\s?]+)\s+malicious\??$",
        r"\bcheck\s+(?:ip|domain|hash|url|email)?\s*([^\s?]+)",
        r"\blookup\s+(?:ip|domain|hash|url|email)?\s*([^\s?]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized_query)
        if match:
            return match.group(1).strip(" ?.,;")
    return None


def _is_failed_login(item: dict) -> bool:
    text = _search_text([item])
    return "failed login" in text or "failed_login" in text or "4625" in text or "brute force" in text


def _is_dos(item: dict) -> bool:
    text = _search_text([item])
    return "ddos" in text or "dos_attack" in text or "dos attack" in text or "denial of service" in text


def _search_text(items: list[dict]) -> str:
    values = []
    keys = [
        "title",
        "description",
        "message",
        "event_type",
        "severity",
        "security_detection_type",
        "matched_rule_name",
        "mitre_technique",
        "mitre_technique_name",
    ]
    for item in items:
        values.extend(str(item.get(key) or "") for key in keys)
    return " ".join(values).lower()


def _mitre_from_alerts(alerts: list[dict]) -> list[dict]:
    mappings = []
    seen = set()
    for alert in alerts:
        mapping = {
            "tactic_id": alert.get("mitre_tactic_id"),
            "tactic_name": alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
            "technique_id": alert.get("mitre_technique_id"),
            "technique_name": alert.get("mitre_technique_name") or alert.get("mitre_technique"),
            "subtechnique_id": alert.get("mitre_subtechnique_id"),
            "subtechnique_name": alert.get("mitre_subtechnique_name"),
        }
        key = tuple(mapping.values())
        if key in seen or not any(mapping.values()):
            continue
        seen.add(key)
        mappings.append(mapping)
    return mappings


def _mitre_from_incident(incident: dict) -> list[dict]:
    mappings = incident.get("mitre_mappings") or []
    if mappings:
        return mappings
    return _mitre_from_alerts([incident])


def _affected_assets(incident: dict, alerts: list[dict]) -> list[str]:
    assets = set()
    assets.update(str(item) for item in incident.get("related_hosts", []) if item)
    assets.update(str(item) for item in incident.get("related_ips", []) if item)
    for alert in alerts:
        if _host(alert):
            assets.add(_host(alert))
        if _ip(alert):
            assets.add(_ip(alert))
        if alert.get("username"):
            assets.add(str(alert["username"]))
    return sorted(assets)


def _timeline(incident: dict, alerts: list[dict]) -> list[dict]:
    events = incident.get("timeline_events") or alerts
    timeline = []
    for item in sorted(events, key=lambda value: str(value.get("timestamp") or "")):
        timeline.append(
            {
                "timestamp": _string_or_none(item.get("timestamp")),
                "event_type": item.get("event_type"),
                "description": item.get("message") or item.get("title") or item.get("description") or "Security event observed.",
                "severity": item.get("severity"),
                "source_ip": item.get("source_ip") or item.get("ip_address"),
                "host": item.get("host") or item.get("hostname") or item.get("source"),
            }
        )
    if not timeline:
        timeline.append(
            {
                "timestamp": _string_or_none(incident.get("timestamp")),
                "event_type": "incident_created",
                "description": incident.get("description") or incident.get("title") or "Incident created.",
                "severity": incident.get("severity"),
                "source_ip": None,
                "host": None,
            }
        )
    return timeline


def _executive_summary(incident: dict, alerts: list[dict], assets: list[str]) -> str:
    severity = incident.get("severity") or "unknown"
    alert_count = len(alerts)
    asset_text = ", ".join(assets[:5]) if assets else "no enriched assets"
    return f"{severity.title()} incident with {alert_count} related alert(s) affecting {asset_text}."


def _root_cause_guess(incident: dict, alerts: list[dict]) -> str:
    text = _search_text([incident, *alerts])
    if "failed login" in text or "brute force" in text:
        return "Likely credential access attempt caused by repeated authentication failures."
    if "ddos" in text or "dos" in text:
        return "Likely availability attack caused by elevated request volume or endpoint errors."
    if "malware" in text:
        return "Possible malware execution or detection from endpoint telemetry."
    return "Insufficient deterministic evidence for a single root cause."


def _incident_title(incident: dict, alerts: list[dict]) -> str:
    if alerts:
        return f"{alerts[0].get('severity', 'Security').title()} activity: {alerts[0].get('event_type', 'alert')}"
    return incident.get("description") or "Security incident"


def _analyst_next_steps(incident: dict, alerts: list[dict]) -> list[str]:
    steps = [
        "Validate alert evidence and affected tenant scope.",
        "Review related alerts, timeline, users, hosts, and source IPs.",
    ]
    if any(_is_failed_login(alert) for alert in alerts):
        steps.append("Check authentication logs for password spraying or brute-force patterns.")
    if any(_is_dos(alert) for alert in alerts):
        steps.append("Review traffic rates, endpoint errors, and source IP distribution.")
    if _mitre_from_alerts(alerts) or _mitre_from_incident(incident):
        steps.append("Use MITRE mapping to hunt for adjacent tactics and techniques.")
    return steps


async def _preview_alerts(organization_id: str, filters: dict[str, Any]) -> dict:
    matches = []
    cursor = alerts_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for alert in cursor:
        item = serialize_document(alert)
        if _matches_filters(item, filters):
            matches.append(item)
    return {"count": len(matches), "sample": [_preview_document(item) for item in matches[:5]]}


async def _preview_incidents(organization_id: str, filters: dict[str, Any]) -> dict:
    matches = []
    cursor = incidents_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for incident in cursor:
        item = serialize_document(incident)
        if _matches_filters(item, filters):
            matches.append(item)
    return {"count": len(matches), "sample": [_preview_document(item) for item in matches[:5]]}


async def _blocked_ips_preview(organization_id: str) -> dict:
    ips = set()
    cursor = response_actions_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for action in cursor:
        item = serialize_document(action)
        action_text = " ".join(str(value) for value in item.get("automated_actions", []))
        if item.get("ip_address") and ("block" in action_text.lower() or item.get("action_type") == "block_ip"):
            ips.add(str(item["ip_address"]))
    cursor = security_blocks_collection.find({"organization_id": organization_id}).sort("blocked_at", -1)
    async for block in cursor:
        item = serialize_document(block)
        if item.get("ip_address"):
            ips.add(str(item["ip_address"]))
    return {"count": len(ips), "sample": sorted(ips)[:10]}


def _matches_filters(item: dict, filters: dict[str, Any]) -> bool:
    for key, value in filters.items():
        if key == "event_type" and value == "failed_login" and not _is_failed_login(item):
            return False
        if key == "event_type" and value == "dos_ddos" and not _is_dos(item):
            return False
        if key == "severity" and _lower(item.get("severity")) != value:
            return False
        if key == "host" and _lower(_host(item)) != _lower(value):
            return False
        if key == "mitre_technique_id" and _lower(item.get("mitre_technique_id")) != _lower(value):
            return False
        if key == "from":
            timestamp = _parse_datetime(item.get("timestamp"))
            cutoff = _parse_datetime(value)
            if timestamp is None or cutoff is None or timestamp < cutoff:
                return False
    return True


def _preview_document(item: dict) -> dict:
    return {
        "id": str(item.get("_id") or item.get("id") or ""),
        "title": item.get("title") or item.get("message") or item.get("event_type"),
        "severity": item.get("severity"),
        "timestamp": _string_or_none(item.get("timestamp")),
        "source_ip": item.get("source_ip") or item.get("ip_address"),
        "host": _host(item),
    }


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _ip(item: dict) -> str:
    return str(item.get("source_ip") or item.get("ip_address") or "")


def _host(item: dict) -> str:
    return str(item.get("hostname") or item.get("host") or item.get("source") or "")


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _clamp(value: int | float) -> int:
    return max(0, min(100, int(round(value))))


def _unique_actions(actions: list[str]) -> list[str]:
    return [action for action in dict.fromkeys(actions) if action in ACTION_VALUES]
