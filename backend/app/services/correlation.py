from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from bson import ObjectId

from app.common.mongo import serialize_document
from app.db.client import alerts_collection, correlated_incidents_collection, incidents_collection
from app.realtime.events import build_realtime_event
from app.realtime.pubsub import publish_realtime_event
from app.services.investigation_summary import generate_investigation_summary


CORRELATION_WINDOW = timedelta(minutes=30)
MAX_RECENT_ALERTS = 100

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

TACTIC_TO_STAGE = {
    "initial access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    "defense evasion": "Defense Evasion",
    "credential access": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _alert_id(alert: dict[str, Any]) -> str:
    return str(alert.get("_id") or alert.get("id") or "")


def _incident_query(incident_id: str) -> dict[str, Any]:
    if ObjectId.is_valid(incident_id):
        return {"_id": ObjectId(incident_id)}
    return {"_id": incident_id}


def _timestamp(alert: dict[str, Any]) -> datetime:
    value = alert.get("timestamp")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _host(alert: dict[str, Any]) -> str:
    return str(alert.get("hostname") or alert.get("host") or alert.get("source") or "")


def _tactic(alert: dict[str, Any]) -> str:
    return str(alert.get("mitre_tactic_name") or alert.get("mitre_tactic") or "").lower()


def _severity(alert: dict[str, Any]) -> int:
    return SEVERITY_RANK.get(str(alert.get("severity") or "info").lower(), 0)


def _is_failed_login(alert: dict[str, Any]) -> bool:
    text = f"{alert.get('event_type', '')} {alert.get('message', '')}".lower()
    return ("login" in text or "auth" in text or "ssh" in text or "sudo" in text) and (
        "failed" in text or "failure" in text
    )


def _is_success_login(alert: dict[str, Any]) -> bool:
    text = f"{alert.get('event_type', '')} {alert.get('message', '')}".lower()
    return ("login" in text or "auth" in text or "ssh" in text or "sudo" in text) and (
        "success" in text or "accepted" in text
    )


def _is_suspicious_process(alert: dict[str, Any]) -> bool:
    text = f"{alert.get('event_type', '')} {alert.get('message', '')}".lower()
    return "process" in text and ("suspicious" in text or "execution" in text)


def _has_escalating_severity(alerts: list[dict[str, Any]]) -> bool:
    ordered = sorted(alerts, key=_timestamp)
    ranks = [_severity(alert) for alert in ordered]
    return any(later > earlier for earlier, later in zip(ranks, ranks[1:]))


def _has_failed_then_success(alerts: list[dict[str, Any]]) -> bool:
    seen_failures = 0
    for alert in sorted(alerts, key=_timestamp):
        if _is_failed_login(alert):
            seen_failures += 1
        elif seen_failures >= 2 and _is_success_login(alert):
            return True
    return False


def _attack_stage(alerts: list[dict[str, Any]]) -> str:
    for alert in sorted(alerts, key=_timestamp, reverse=True):
        stage = TACTIC_TO_STAGE.get(_tactic(alert))
        if stage:
            return stage
    return "Initial Access"


def _related(current: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if _alert_id(current) == _alert_id(candidate):
        return False
    if current.get("ip_address") and current.get("ip_address") == candidate.get("ip_address"):
        return True
    if _host(current) and _host(current) == _host(candidate):
        return True
    if _tactic(current) and _tactic(current) == _tactic(candidate):
        return True
    return False


def calculate_correlation_score(alerts: list[dict[str, Any]]) -> int:
    if not alerts:
        return 0

    score = 10
    ips = {str(alert.get("ip_address")) for alert in alerts if alert.get("ip_address")}
    hosts = {_host(alert) for alert in alerts if _host(alert)}
    tactics = {_tactic(alert) for alert in alerts if _tactic(alert)}

    if len(alerts) > 1:
        score += 10
    if len(ips) == 1 and ips:
        score += 20
    if len(hosts) == 1 and hosts:
        score += 15
    if len(tactics) == 1 and tactics:
        score += 15
    if _has_escalating_severity(alerts):
        score += 15
    if _has_failed_then_success(alerts):
        score += 20
    if sum(1 for alert in alerts if _is_suspicious_process(alert)) >= 2:
        score += 15
    if len(hosts | ips) >= 3:
        score += 10

    return min(score, 100)


def build_correlation_document(
    alerts: list[dict[str, Any]],
    *,
    correlation_id: str | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    ordered = sorted(alerts, key=_timestamp)
    related_alert_ids = [_alert_id(alert) for alert in ordered if _alert_id(alert)]
    score = calculate_correlation_score(ordered)
    stage = _attack_stage(ordered)
    now = datetime.now(timezone.utc)
    organization_id = str(ordered[0].get("organization_id"))
    hosts = sorted({_host(alert) for alert in ordered if _host(alert)})
    ips = sorted({str(alert.get("ip_address")) for alert in ordered if alert.get("ip_address")})
    tactics = sorted({str(alert.get("mitre_tactic_name") or alert.get("mitre_tactic")) for alert in ordered if alert.get("mitre_tactic_name") or alert.get("mitre_tactic")})
    techniques = sorted({str(alert.get("mitre_technique_id") or alert.get("mitre_technique")) for alert in ordered if alert.get("mitre_technique_id") or alert.get("mitre_technique")})

    return {
        "correlation_id": correlation_id or str(uuid4()),
        "organization_id": organization_id,
        "incident_id": incident_id,
        "correlation_score": score,
        "attack_stage": stage,
        "related_alert_ids": related_alert_ids,
        "related_hosts": hosts,
        "related_ips": ips,
        "mitre_tactics": tactics,
        "mitre_techniques": techniques,
        "summary": generate_investigation_summary(ordered),
        "first_seen": _timestamp(ordered[0]),
        "last_seen": _timestamp(ordered[-1]),
        "status": "active",
        "updated_at": now,
        "created_at": now,
    }


async def _recent_alerts(current: dict[str, Any], alerts_store=alerts_collection) -> list[dict[str, Any]]:
    lower_bound = _timestamp(current) - CORRELATION_WINDOW
    cursor = (
        alerts_store.find({"organization_id": current["organization_id"]})
        .sort("timestamp", -1)
        .limit(MAX_RECENT_ALERTS)
    )
    alerts = []
    async for alert in cursor:
        if _timestamp(alert) >= lower_bound:
            alerts.append(alert)
    return alerts


async def _find_existing_group(
    organization_id: str,
    alert_ids: list[str],
    correlated_store=correlated_incidents_collection,
) -> dict[str, Any] | None:
    cursor = correlated_store.find({"organization_id": organization_id}).sort(
        "updated_at", -1
    ).limit(50)
    wanted = set(alert_ids)
    async for group in cursor:
        if wanted.intersection(set(group.get("related_alert_ids", []))):
            return group
    return None


async def _create_incident_for_group(
    group: dict[str, Any],
    alerts: list[dict[str, Any]],
    incidents_store=incidents_collection,
) -> str:
    highest = max(alerts, key=_severity)
    incident = {
        "title": f"{group['attack_stage']} attack chain detected",
        "description": group["summary"],
        "severity": highest.get("severity", "medium"),
        "status": "new",
        "assigned_to": None,
        "assigned_to_user_id": None,
        "assigned_to_email": None,
        "investigation_notes": "",
        "organization_id": group["organization_id"],
        "correlation_id": group["correlation_id"],
        "related_alert_ids": group["related_alert_ids"],
        "attack_stage": group["attack_stage"],
        "investigation_summary": group["summary"],
        "timestamp": datetime.now(timezone.utc),
    }
    result = await incidents_store.insert_one(incident)
    return str(result.inserted_id)


async def correlate_alert(
    alert: dict[str, Any],
    incident_id: str | None = None,
    *,
    alerts_store=alerts_collection,
    incidents_store=incidents_collection,
    correlated_store=correlated_incidents_collection,
) -> dict[str, Any] | None:
    candidates = [
        candidate for candidate in await _recent_alerts(alert, alerts_store) if _related(alert, candidate)
    ]
    alerts = [alert, *candidates]
    score = calculate_correlation_score(alerts)
    if len(alerts) < 2 or score < 35:
        return None

    alert_ids = [_alert_id(item) for item in alerts if _alert_id(item)]
    existing = await _find_existing_group(alert["organization_id"], alert_ids, correlated_store)
    group = build_correlation_document(
        alerts,
        correlation_id=existing.get("correlation_id") if existing else None,
        incident_id=incident_id or (existing.get("incident_id") if existing else None),
    )
    if not group.get("incident_id") and score >= 45:
        group["incident_id"] = await _create_incident_for_group(group, alerts, incidents_store)

    if existing:
        await correlated_store.update_one(
            {"_id": existing["_id"]},
            {
                "$set": {
                    key: value
                    for key, value in group.items()
                    if key not in {"created_at", "correlation_id"}
                }
            },
        )
        event_type = "correlation.updated"
    else:
        await correlated_store.insert_one(group)
        event_type = "correlation.created"

    if group.get("incident_id"):
        await incidents_store.update_one(
            _incident_query(group["incident_id"]),
            {
                "$set": {
                    "correlation_id": group["correlation_id"],
                    "related_alert_ids": group["related_alert_ids"],
                    "attack_stage": group["attack_stage"],
                    "investigation_summary": group["summary"],
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    payload = {
        "correlation_id": group["correlation_id"],
        "incident_id": group.get("incident_id"),
        "correlation_score": group["correlation_score"],
        "attack_stage": group["attack_stage"],
        "related_alert_ids": group["related_alert_ids"],
        "summary": group["summary"],
    }
    await publish_realtime_event(
        build_realtime_event(
            event_type=event_type,
            organization_id=group["organization_id"],
            payload=payload,
        )
    )
    if group.get("incident_id"):
        await publish_realtime_event(
            build_realtime_event(
                event_type="timeline.updated",
                organization_id=group["organization_id"],
                payload=payload,
            )
        )

    return serialize_document(group)
