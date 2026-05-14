from collections import Counter
from typing import Any


def _event_label(alert: dict[str, Any]) -> str:
    return str(alert.get("event_type") or "activity").replace("_", " ")


def _host_label(alerts: list[dict[str, Any]]) -> str:
    for alert in alerts:
        host = alert.get("hostname") or alert.get("host") or alert.get("source")
        if host:
            return str(host)
    return "an observed host"


def _mitre_label(alerts: list[dict[str, Any]]) -> str:
    techniques = []
    tactics = []
    for alert in alerts:
        technique = alert.get("mitre_technique_id")
        tactic = alert.get("mitre_tactic_id")
        if technique and technique not in techniques:
            techniques.append(str(technique))
        if tactic and tactic not in tactics:
            tactics.append(str(tactic))
    labels = [*techniques[:3], *tactics[:3]]
    return " and ".join(labels) if labels else "available MITRE ATT&CK metadata"


def _has_success_after_failures(alerts: list[dict[str, Any]]) -> bool:
    ordered = sorted(alerts, key=lambda item: str(item.get("timestamp") or ""))
    seen_failure = False
    for alert in ordered:
        text = f"{alert.get('event_type', '')} {alert.get('message', '')}".lower()
        if "failed" in text or "failure" in text:
            seen_failure = True
        if seen_failure and "success" in text:
            return True
    return False


def generate_investigation_summary(alerts: list[dict[str, Any]]) -> str:
    if not alerts:
        return "No related alert activity is currently available for this investigation."

    host = _host_label(alerts)
    mitre = _mitre_label(alerts)
    severities = Counter(str(alert.get("severity") or "info").lower() for alert in alerts)
    event_types = Counter(_event_label(alert) for alert in alerts)
    top_event = event_types.most_common(1)[0][0]
    top_severity = severities.most_common(1)[0][0]

    if _has_success_after_failures(alerts):
        return (
            "Multiple failed login attempts followed by successful activity detected on "
            f"{host}. Activity maps to MITRE ATT&CK {mitre}."
        )

    if len(alerts) > 1:
        return (
            f"{len(alerts)} related {top_severity} alerts involving {top_event} were detected "
            f"on {host}. Activity maps to MITRE ATT&CK {mitre}."
        )

    return (
        f"A {top_severity} {top_event} alert was detected on {host}. "
        f"Activity maps to MITRE ATT&CK {mitre}."
    )
