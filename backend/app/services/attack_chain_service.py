from datetime import datetime, timedelta, timezone
from typing import Any

from app.db.client import alerts_collection, incidents_collection
from app.repositories.attack_chain_repository import (
    create_attack_chain,
    find_existing_chain_for_alert_group,
    get_attack_chain,
    update_attack_chain,
)
from app.services.mitre_mapper import map_alert_to_mitre


STAGES = (
    "INITIAL_ACCESS",
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
)

SEVERITY_WEIGHTS = {
    "low": 0.2,
    "info": 0.1,
    "medium": 0.6,
    "high": 1.2,
    "critical": 2.0,
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _alert_id(alert: dict[str, Any]) -> str:
    return _text(alert.get("_id") or alert.get("id") or alert.get("alert_id"))


def _host(alert: dict[str, Any]) -> str:
    return _text(alert.get("hostname") or alert.get("host") or alert.get("source"))


def _user(alert: dict[str, Any]) -> str:
    return _text(alert.get("username") or alert.get("user") or alert.get("account_name"))


def _source_ip(alert: dict[str, Any]) -> str:
    return _text(alert.get("source_ip") or alert.get("ip_address") or alert.get("src_ip"))


def _destination_ip(alert: dict[str, Any]) -> str:
    return _text(alert.get("destination_ip") or alert.get("dest_ip") or alert.get("target_ip"))


def _session(alert: dict[str, Any]) -> str:
    return _text(alert.get("session_id") or alert.get("logon_id") or alert.get("process_guid"))


def _process(alert: dict[str, Any]) -> str:
    return _text(alert.get("process_name") or alert.get("process") or alert.get("parent_process_name"))


def _identity_keys(alert: dict[str, Any]) -> set[tuple[str, str]]:
    values = {
        ("host", _host(alert).lower()),
        ("user", _user(alert).lower()),
        ("source_ip", _source_ip(alert)),
        ("destination_ip", _destination_ip(alert)),
        ("session", _session(alert)),
        ("process", _process(alert).lower()),
    }
    return {(key, value) for key, value in values if value}


async def fetch_recent_alerts(organization_id: str, lookback_hours: int) -> list[dict[str, Any]]:
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    alerts = []
    cursor = alerts_collection.find(
        {"organization_id": organization_id, "timestamp": {"$gte": since}}
    ).sort("timestamp", 1)
    async for alert in cursor:
        alert["timestamp"] = _normalize_timestamp(alert.get("timestamp"))
        alerts.append(alert)
    return alerts


async def _related_incident_ids(organization_id: str, alert_ids: list[str]) -> list[str]:
    if not alert_ids:
        return []
    ids = []
    cursor = incidents_collection.find(
        {
            "organization_id": organization_id,
            "$or": [
                {"alert_id": {"$in": alert_ids}},
                {"related_alert_ids": {"$in": alert_ids}},
            ],
        }
    )
    async for incident in cursor:
        incident_id = _text(incident.get("_id") or incident.get("id") or incident.get("incident_id"))
        if incident_id:
            ids.append(incident_id)
    return sorted(set(ids))


def _are_related(left: dict[str, Any], right: dict[str, Any], window: timedelta) -> bool:
    left_time = _normalize_timestamp(left.get("timestamp"))
    right_time = _normalize_timestamp(right.get("timestamp"))
    if abs(left_time - right_time) > window:
        return False
    return bool(_identity_keys(left) & _identity_keys(right))


def group_related_alerts(
    alerts: list[dict[str, Any]],
    window_minutes: int = 120,
) -> list[list[dict[str, Any]]]:
    if not alerts:
        return []

    window = timedelta(minutes=window_minutes)
    groups: list[list[dict[str, Any]]] = []
    key_to_group: dict[tuple[str, str], int] = {}

    for alert in sorted(alerts, key=lambda item: _normalize_timestamp(item.get("timestamp"))):
        related_indexes = set()
        for key in _identity_keys(alert):
            group_index = key_to_group.get(key)
            if group_index is None:
                continue
            if any(_are_related(alert, existing, window) for existing in groups[group_index]):
                related_indexes.add(group_index)

        if not related_indexes:
            group_index = len(groups)
            groups.append([alert])
        else:
            group_index = min(related_indexes)
            groups[group_index].append(alert)
            for other_index in sorted(related_indexes - {group_index}, reverse=True):
                groups[group_index].extend(groups[other_index])
                del groups[other_index]
                key_to_group = {
                    key: (
                        group_index
                        if value == other_index
                        else value - 1
                        if value > other_index
                        else value
                    )
                    for key, value in key_to_group.items()
                }

        for key in _identity_keys(alert):
            key_to_group[key] = group_index

    return [
        sorted(group, key=lambda item: _normalize_timestamp(item.get("timestamp")))
        for group in groups
        if len({_alert_id(alert) for alert in group if _alert_id(alert)}) >= 2
    ]


def _stage_for_alert(alert: dict[str, Any], mitre: list[dict[str, str]]) -> str:
    text = " ".join(
        _text(alert.get(key))
        for key in (
            "title",
            "event_type",
            "message",
            "process_name",
            "command_line",
            "mitre_tactic_name",
            "mitre_tactic",
        )
    ).lower()
    technique_ids = {mapping["technique_id"] for mapping in mitre}
    if "exfil" in text or "large outbound" in text or "data upload" in text or "T1041" in technique_ids:
        return "EXFILTRATION"
    if "lateral" in text or "remote login" in text or "rdp" in text or "ssh" in text or "T1021" in technique_ids:
        return "LATERAL_MOVEMENT"
    if "credential" in text or "mimikatz" in text or "lsass" in text or "T1003" in technique_ids:
        return "CREDENTIAL_ACCESS"
    if "privilege" in text or "sudo" in text or "escalation" in text:
        return "PRIVILEGE_ESCALATION"
    if "scheduled task" in text or "cron" in text or "startup folder" in text or "T1053" in technique_ids:
        return "PERSISTENCE"
    if "powershell" in text or "cmd.exe" in text or "bash" in text or "shell" in text or "T1059" in technique_ids:
        return "EXECUTION"
    if "login" in text or "download" in text or "payload" in text or "T1105" in technique_ids:
        return "INITIAL_ACCESS"
    return "EXECUTION"


def _dedupe_dicts(items: list[dict[str, str]], key: str) -> list[dict[str, str]]:
    result = []
    seen = set()
    for item in items:
        value = item.get(key)
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(item)
    return result


def _build_timeline(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = []
    for alert in sorted(alerts, key=lambda item: _normalize_timestamp(item.get("timestamp"))):
        mitre = map_alert_to_mitre(alert)
        stage = _stage_for_alert(alert, mitre)
        timeline.append(
            {
                "alert_id": _alert_id(alert),
                "timestamp": _normalize_timestamp(alert.get("timestamp")),
                "title": _text(alert.get("title")) or None,
                "event_type": _text(alert.get("event_type")) or None,
                "severity": _text(alert.get("severity")).lower() or None,
                "host": _host(alert) or None,
                "user": _user(alert) or None,
                "source_ip": _source_ip(alert) or None,
                "destination_ip": _destination_ip(alert) or None,
                "process_name": _process(alert) or None,
                "stage": stage,
                "mitre_techniques": mitre,
                "message": _text(alert.get("message")) or None,
            }
        )
    return timeline


def calculate_risk_score(alerts: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> float:
    risk = min(len(alerts) * 0.45, 2.5)
    severities = [_text(alert.get("severity")).lower() for alert in alerts]
    risk += sum(SEVERITY_WEIGHTS.get(severity, 0.3) for severity in severities)
    hosts = {_host(alert).lower() for alert in alerts if _host(alert)}
    users = {_user(alert).lower() for alert in alerts if _user(alert)}
    risk += min((len(hosts) + len(users)) * 0.35, 2.0)
    stages = {item.get("stage") for item in timeline}
    if "CREDENTIAL_ACCESS" in stages:
        risk += 1.5
    if "LATERAL_MOVEMENT" in stages:
        risk += 1.25
    if "EXFILTRATION" in stages:
        risk += 1.5
    if len(timeline) >= 3:
        duration = (
            _normalize_timestamp(timeline[-1].get("timestamp"))
            - _normalize_timestamp(timeline[0].get("timestamp"))
        ).total_seconds() / 60
        if duration <= 60:
            risk += 1.0
        elif duration <= 180:
            risk += 0.5
    return round(max(0.0, min(risk, 10.0)), 1)


def _severity_from_risk(risk_score: float) -> str:
    if risk_score >= 8.5:
        return "critical"
    if risk_score >= 6.5:
        return "high"
    if risk_score >= 4.0:
        return "medium"
    return "low"


def _confidence(alerts: list[dict[str, Any]], timeline: list[dict[str, Any]]) -> float:
    techniques = {
        technique["technique_id"]
        for item in timeline
        for technique in item.get("mitre_techniques", [])
    }
    value = 0.35 + min(len(alerts), 6) * 0.07 + min(len(techniques), 5) * 0.06
    return round(min(value, 1.0), 2)


def _summary(chain: dict[str, Any]) -> str:
    stages = ", ".join(stage.replace("_", " ").title() for stage in chain["attack_stages"])
    hosts = ", ".join(chain["affected_hosts"][:4]) or "unknown hosts"
    users = ", ".join(chain["affected_users"][:4]) or "unknown users"
    techniques = ", ".join(
        f"{item['technique_id']} {item['technique_name']}"
        for item in chain["mitre_techniques"][:5]
    ) or "no mapped MITRE techniques"
    return (
        f"{len(chain['related_alert_ids'])} related alerts form a probable attack chain across "
        f"{hosts} affecting {users}. Observed stages: {stages or 'Execution'}. "
        f"Mapped techniques include {techniques}. The current risk score is "
        f"{chain['risk_score']}/10 with {chain['confidence_score']:.0%} correlation confidence."
    )


def _recommendations(stages: set[str], risk_score: float) -> list[str]:
    actions = [
        "Preserve relevant endpoint, authentication, and network logs for the full timeline window.",
        "Validate each affected host for active processes, suspicious persistence, and outbound connections.",
    ]
    if "CREDENTIAL_ACCESS" in stages:
        actions.append("Reset credentials for affected users and investigate LSASS/hash access artifacts.")
    if "LATERAL_MOVEMENT" in stages:
        actions.append("Review RDP, SSH, SMB, and WinRM sessions and restrict remote access paths until contained.")
    if "EXFILTRATION" in stages:
        actions.append("Block suspicious outbound destinations and quantify possible data transfer scope.")
    if risk_score >= 8:
        actions.append("Escalate to incident command and isolate high-confidence affected hosts.")
    return actions


def _chain_subject(alerts: list[dict[str, Any]], source_ips: list[str]) -> str:
    host = _host(alerts[0]) if alerts else ""
    if host:
        return host
    if source_ips:
        return source_ips[0]
    return "multiple assets"


async def build_attack_chain_from_group(
    organization_id: str,
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    timeline = _build_timeline(alerts)
    stages = [stage for stage in STAGES if stage in {item.get("stage") for item in timeline}]
    mitre = _dedupe_dicts(
        [technique for item in timeline for technique in item.get("mitre_techniques", [])],
        "technique_id",
    )
    risk_score = calculate_risk_score(alerts, timeline)
    source_ips = sorted({_source_ip(alert) for alert in alerts if _source_ip(alert)})
    first_stage = stages[0].replace("_", " ").title() if stages else "Correlated Activity"
    chain = {
        "title": f"Threat story: {first_stage} on {_chain_subject(alerts, source_ips)}",
        "status": "open",
        "severity": _severity_from_risk(risk_score),
        "risk_score": risk_score,
        "confidence_score": _confidence(alerts, timeline),
        "related_alert_ids": [_alert_id(alert) for alert in alerts if _alert_id(alert)],
        "related_incident_ids": await _related_incident_ids(
            organization_id,
            [_alert_id(alert) for alert in alerts if _alert_id(alert)],
        ),
        "affected_hosts": sorted({_host(alert) for alert in alerts if _host(alert)}),
        "affected_users": sorted({_user(alert) for alert in alerts if _user(alert)}),
        "source_ips": source_ips,
        "destination_ips": sorted(
            {_destination_ip(alert) for alert in alerts if _destination_ip(alert)}
        ),
        "mitre_techniques": mitre,
        "attack_stages": stages,
        "timeline": timeline,
        "ai_summary": "",
        "recommended_actions": [],
    }
    chain["ai_summary"] = _summary(chain)
    chain["recommended_actions"] = _recommendations(set(stages), risk_score)
    return chain


async def generate_attack_chains(organization_id: str, lookback_hours: int = 24) -> dict[str, Any]:
    bounded_lookback = max(1, min(int(lookback_hours), 24 * 14))
    alerts = await fetch_recent_alerts(organization_id, bounded_lookback)
    groups = group_related_alerts(alerts)
    chains = []
    for group in groups:
        candidate = await build_attack_chain_from_group(organization_id, group)
        existing = await find_existing_chain_for_alert_group(
            organization_id,
            candidate["related_alert_ids"],
        )
        if existing:
            merged_alert_ids = sorted(
                set(existing.get("related_alert_ids", [])) | set(candidate["related_alert_ids"])
            )
            if merged_alert_ids != existing.get("related_alert_ids"):
                existing = await update_attack_chain(
                    existing["id"],
                    organization_id,
                    {
                        **candidate,
                        "status": existing.get("status", "open"),
                        "related_alert_ids": merged_alert_ids,
                    },
                )
            chains.append(existing)
        else:
            chains.append(await create_attack_chain(organization_id, candidate))
    return {"items": chains, "generated": len(chains), "lookback_hours": bounded_lookback}


async def get_attack_chain_story(chain_id: str, organization_id: str) -> dict[str, Any]:
    chain = await get_attack_chain(chain_id, organization_id)
    return {
        "chain_id": chain["id"],
        "timeline": chain.get("timeline", []),
        "ai_summary": chain.get("ai_summary", ""),
        "recommended_actions": chain.get("recommended_actions", []),
    }


def build_attack_chain_graph(chain: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {
        f"chain-{chain['id']}": {
            "id": f"chain-{chain['id']}",
            "type": "attack_chain",
            "label": chain.get("title") or "Attack chain",
            "severity": chain.get("severity"),
            "metadata": {"risk_score": chain.get("risk_score"), "status": chain.get("status")},
        }
    }
    edges: dict[str, dict[str, Any]] = {}

    def add_node(
        node_id: str,
        node_type: str,
        label: str,
        severity: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if label and node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "label": label,
                "severity": severity,
                "metadata": metadata or {},
            }

    def add_edge(source: str, target: str, label: str) -> None:
        edge_id = f"{source}->{target}:{label}"
        if source != target:
            edges[edge_id] = {"id": edge_id, "source": source, "target": target, "label": label}

    chain_node = f"chain-{chain['id']}"
    previous_alert_node = ""
    for item in chain.get("timeline", []):
        alert_id = item.get("alert_id") or f"{item.get('timestamp')}-{item.get('event_type')}"
        alert_node = f"alert-{alert_id}"
        add_node(
            alert_node,
            "alert",
            item.get("title") or item.get("event_type") or "Alert",
            item.get("severity"),
            item,
        )
        add_edge(alert_node, chain_node, "correlated")
        if previous_alert_node:
            add_edge(previous_alert_node, alert_node, "then")
        previous_alert_node = alert_node
        for node_type, value in (
            ("host", item.get("host")),
            ("user", item.get("user")),
            ("source_ip", item.get("source_ip")),
            ("destination_ip", item.get("destination_ip")),
        ):
            if value:
                node_id = f"{node_type}-{value}".replace(" ", "-")
                add_node(node_id, node_type, value, metadata={node_type: value})
                add_edge(node_id, alert_node, "observed")
        for technique in item.get("mitre_techniques", []):
            technique_id = technique.get("technique_id")
            if technique_id:
                node_id = f"mitre-{technique_id}"
                add_node(
                    node_id,
                    "mitre_technique",
                    f"{technique_id} {technique.get('technique_name')}",
                    metadata=technique,
                )
                add_edge(alert_node, node_id, "mapped")
    return {"chain_id": chain["id"], "nodes": list(nodes.values()), "edges": list(edges.values())}


async def get_attack_chain_graph(chain_id: str, organization_id: str) -> dict[str, Any]:
    chain = await get_attack_chain(chain_id, organization_id)
    return build_attack_chain_graph(chain)
