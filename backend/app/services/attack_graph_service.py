import re
from typing import Any

from app.schemas.attack_graph import AttackGraphEdge, AttackGraphNode, AttackGraphResponse
from app.services.incidents import get_incident


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _slug(prefix: str, value: Any) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", _text(value).lower()).strip("-")
    return f"{prefix}-{normalized or 'unknown'}"


def _incident_id(incident: dict[str, Any]) -> str:
    return _text(incident.get("_id") or incident.get("id") or incident.get("incident_id"))


def _alert_label(alert: dict[str, Any]) -> str:
    return (
        _text(alert.get("title"))
        or _text(alert.get("message"))
        or _text(alert.get("event_type"))
        or "Alert"
    )


def _soar_label(action: dict[str, Any]) -> str:
    automated_actions = [_text(item) for item in action.get("automated_actions", []) if _text(item)]
    if automated_actions:
        return automated_actions[0]
    action_type = _text(action.get("action_type")).replace("_", " ").title()
    if action_type == "Block Ip":
        return "Block IP"
    return action_type or "SOAR action"


def _mitre_label(mapping: dict[str, Any]) -> str:
    technique_id = _text(mapping.get("technique_id") or mapping.get("mitre_technique_id"))
    technique_name = _text(mapping.get("technique_name") or mapping.get("mitre_technique_name"))
    tactic_name = _text(mapping.get("tactic_name") or mapping.get("mitre_tactic_name"))
    label = " ".join(part for part in [technique_id, technique_name] if part)
    if not label:
        label = tactic_name
    if tactic_name and tactic_name not in label:
        label = f"{label} ({tactic_name})" if label else tactic_name
    return label or "MITRE mapping"


def _alert_contexts(incident: dict[str, Any]) -> list[dict[str, Any]]:
    contexts: dict[str, dict[str, Any]] = {}

    for alert in incident.get("related_alerts", []) or []:
        alert_id = _text(alert.get("_id") or alert.get("id"))
        if alert_id:
            contexts[alert_id] = dict(alert)

    for event in incident.get("timeline_events", []) or []:
        alert_id = _text(event.get("alert_id"))
        if not alert_id:
            continue
        current = contexts.setdefault(alert_id, {"_id": alert_id})
        current.setdefault("message", event.get("message"))
        current.setdefault("event_type", event.get("event_type"))
        current.setdefault("severity", event.get("severity"))
        current.setdefault("ip_address", event.get("ip_address"))
        current.setdefault("hostname", event.get("host"))
        current.setdefault("host", event.get("host"))

        mitre = event.get("mitre") or {}
        if mitre:
            current.setdefault("mitre_tactic_id", mitre.get("tactic_id"))
            current.setdefault("mitre_tactic_name", mitre.get("tactic_name"))
            current.setdefault("mitre_technique_id", mitre.get("technique_id"))
            current.setdefault("mitre_technique_name", mitre.get("technique_name"))

    return [contexts[key] for key in sorted(contexts.keys())]


def build_attack_graph(incident: dict[str, Any]) -> AttackGraphResponse:
    nodes: dict[str, AttackGraphNode] = {}
    edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
    incident_id = _incident_id(incident)

    def add_node(
        node_id: str,
        node_type: str,
        label: str,
        severity: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        if not label:
            return ""
        current = nodes.get(node_id)
        if current is None:
            nodes[node_id] = AttackGraphNode(
                id=node_id,
                type=node_type,
                label=label,
                severity=severity,
                metadata=metadata or {},
            )
        else:
            merged_metadata = {**current.metadata, **(metadata or {})}
            if severity and not current.severity:
                current = current.model_copy(update={"severity": severity})
            if merged_metadata != current.metadata:
                current = current.model_copy(update={"metadata": merged_metadata})
            nodes[node_id] = current
        return node_id

    def add_edge(source: str, target: str, label: str) -> None:
        if source and target and source != target:
            edges[(source, target, label)] = AttackGraphEdge(
                source=source,
                target=target,
                label=label,
            )

    incident_node_id = add_node(
        _slug("incident", incident_id or incident.get("title") or "incident"),
        "incident",
        _text(incident.get("title")) or "Incident",
        _text(incident.get("severity")) or None,
        metadata={
            "incident_id": incident_id,
            "status": _text(incident.get("status")),
            "title": _text(incident.get("title")),
        },
    )

    covered_ips: set[str] = set()
    covered_hosts: set[str] = set()
    alert_contexts = _alert_contexts(incident)

    for alert in alert_contexts:
        alert_id = _text(alert.get("_id") or alert.get("id"))
        alert_node_id = add_node(
            _slug("alert", alert_id or _alert_label(alert)),
            "alert",
            _alert_label(alert),
            _text(alert.get("severity")) or None,
            metadata={
                "alert_id": alert_id,
                "event_type": _text(alert.get("event_type")),
                "status": _text(alert.get("status")),
            },
        )
        add_edge(alert_node_id, incident_node_id, "correlated")

        ip_values = [
            _text(alert.get("source_ip")),
            _text(alert.get("ip_address")),
        ]
        ip_values = [value for value in dict.fromkeys(ip_values) if value]
        host_value = _text(alert.get("hostname") or alert.get("host") or alert.get("source"))
        user_value = _text(alert.get("username"))
        endpoint_value = _text(
            alert.get("target_path")
            or (alert.get("evidence") or {}).get("endpoint")
            or incident.get("security_target_path")
        )
        is_dos = _text(alert.get("event_type")) in {"dos_attack", "ddos_attack"} or _text(
            incident.get("security_detection_type")
        ) in {"dos_attack", "ddos_attack"}

        if endpoint_value and is_dos:
            endpoint_node_id = add_node(
                _slug("endpoint", endpoint_value),
                "endpoint",
                endpoint_value,
                metadata={"path": endpoint_value},
            )
            for ip_value in ip_values:
                ip_node_id = add_node(
                    _slug("ip", ip_value),
                    "source_ip",
                    ip_value,
                    _text(alert.get("severity")) or _text(incident.get("severity")) or None,
                    metadata={"ip_address": ip_value},
                )
                covered_ips.add(ip_value)
                add_edge(ip_node_id, endpoint_node_id, "attacked")
            add_edge(endpoint_node_id, alert_node_id, "triggered")
        else:
            host_node_id = ""
            if host_value:
                host_node_id = add_node(
                    _slug("host", host_value),
                    "host",
                    host_value,
                    metadata={"host": host_value},
                )
                covered_hosts.add(host_value)
                for ip_value in ip_values:
                    ip_node_id = add_node(
                        _slug("ip", ip_value),
                        "source_ip",
                        ip_value,
                        _text(alert.get("severity")) or _text(incident.get("severity")) or None,
                        metadata={"ip_address": ip_value},
                    )
                    covered_ips.add(ip_value)
                    add_edge(ip_node_id, host_node_id, "targeted")
            if user_value:
                user_node_id = add_node(
                    _slug("user", user_value),
                    "user",
                    user_value,
                    metadata={"username": user_value},
                )
                if host_node_id:
                    add_edge(host_node_id, user_node_id, "attempted")
                else:
                    for ip_value in ip_values:
                        ip_node_id = add_node(
                            _slug("ip", ip_value),
                            "source_ip",
                            ip_value,
                            _text(alert.get("severity")) or _text(incident.get("severity")) or None,
                            metadata={"ip_address": ip_value},
                        )
                        covered_ips.add(ip_value)
                        add_edge(ip_node_id, user_node_id, "targeted")
                add_edge(user_node_id, alert_node_id, "triggered")
            elif host_node_id:
                add_edge(host_node_id, alert_node_id, "triggered")
            else:
                for ip_value in ip_values:
                    ip_node_id = add_node(
                        _slug("ip", ip_value),
                        "source_ip",
                        ip_value,
                        _text(alert.get("severity")) or _text(incident.get("severity")) or None,
                        metadata={"ip_address": ip_value},
                    )
                    covered_ips.add(ip_value)
                    add_edge(ip_node_id, alert_node_id, "triggered")

        mapping = {
            "tactic_name": alert.get("mitre_tactic_name") or alert.get("mitre_tactic"),
            "technique_id": alert.get("mitre_technique_id"),
            "technique_name": alert.get("mitre_technique_name") or alert.get("mitre_technique"),
        }
        label = _mitre_label(mapping)
        if label != "MITRE mapping":
            mitre_node_id = add_node(
                _slug("mitre", mapping.get("technique_id") or mapping.get("technique_name") or label),
                "mitre_technique",
                label,
                metadata={
                    "technique_id": _text(mapping.get("technique_id")),
                    "technique_name": _text(mapping.get("technique_name")),
                    "tactic_name": _text(mapping.get("tactic_name")),
                },
            )
            add_edge(alert_node_id, mitre_node_id, "mapped to")

    for host_value in sorted(incident.get("related_hosts", []) or []):
        host_text = _text(host_value)
        if host_text and host_text not in covered_hosts:
            host_node_id = add_node(
                _slug("host", host_text),
                "host",
                host_text,
                metadata={"host": host_text},
            )
            add_edge(host_node_id, incident_node_id, "related")

    for ip_value in sorted(incident.get("related_ips", []) or []):
        ip_text = _text(ip_value)
        if ip_text and ip_text not in covered_ips:
            ip_node_id = add_node(
                _slug("ip", ip_text),
                "source_ip",
                ip_text,
                _text(incident.get("severity")) or None,
                metadata={"ip_address": ip_text},
            )
            add_edge(ip_node_id, incident_node_id, "related")

    for mapping in incident.get("mitre_mappings", []) or []:
        label = _mitre_label(mapping)
        if label == "MITRE mapping":
            continue
        mitre_node_id = add_node(
            _slug("mitre", mapping.get("technique_id") or mapping.get("technique_name") or label),
            "mitre_technique",
            label,
            metadata={
                "technique_id": _text(mapping.get("technique_id")),
                "technique_name": _text(mapping.get("technique_name")),
                "tactic_name": _text(mapping.get("tactic_name")),
            },
        )
        add_edge(incident_node_id, mitre_node_id, "mapped to")

    for action in incident.get("soar_actions", []) or []:
        action_id = _text(action.get("_id") or action.get("id"))
        action_node_id = add_node(
            _slug("soar", action_id or _soar_label(action)),
            "soar_action",
            _soar_label(action),
            metadata={
                "response_action_id": action_id,
                "action_type": _text(action.get("action_type")),
                "status": _text(action.get("status")),
            },
        )
        add_edge(incident_node_id, action_node_id, "response")

    return AttackGraphResponse(
        incident_id=incident_id,
        nodes=sorted(nodes.values(), key=lambda item: (item.type, item.label, item.id)),
        edges=sorted(edges.values(), key=lambda item: (item.source, item.target, item.label)),
    )


async def get_incident_attack_graph(incident_id: str, organization_id: str) -> AttackGraphResponse:
    incident = await get_incident(incident_id, organization_id)
    return build_attack_graph(incident)
