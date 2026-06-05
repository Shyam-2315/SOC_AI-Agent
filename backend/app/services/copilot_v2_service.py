from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from app.common.mongo import serialize_document
from app.db.client import alerts_collection, response_actions_collection
from app.repositories.attack_chain_repository import get_attack_chain
from app.schemas.copilot_v2 import (
    CopilotAnswerResponse,
    CopilotContextSummary,
    CopilotQuestionRequest,
    CopilotReportResponse,
    CopilotSuggestion,
)
from app.services.incidents import get_incident
from app.services.mitre_mapper import map_alert_to_mitre
from app.services.threat_intel_service import lookup_ioc


SEVERITY_RISK = {
    "informational": 10,
    "info": 10,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}


async def ask_copilot_v2(
    request: CopilotQuestionRequest,
    organization_id: str,
) -> CopilotAnswerResponse:
    context = await _load_context(request, organization_id)
    return _answer_question(request.question, context)


async def summarize_incident_context(
    incident_id: str,
    organization_id: str,
) -> CopilotContextSummary:
    context = await _incident_context(incident_id, organization_id)
    return context["summary"]


async def summarize_attack_chain_context(
    chain_id: str,
    organization_id: str,
) -> CopilotContextSummary:
    context = await _attack_chain_context(chain_id, organization_id)
    return context["summary"]


async def generate_incident_report(
    incident_id: str,
    organization_id: str,
    report_type: str,
) -> CopilotReportResponse:
    context = await _incident_context(incident_id, organization_id)
    answer = _answer_question(
        "Generate executive summary" if report_type == "executive" else "Generate technical summary",
        context,
    )
    if report_type == "executive":
        summary = (
            f"{answer.context.title} is a {answer.context.severity or 'unknown'} severity incident. "
            f"{answer.short_explanation} Business risk is driven by "
            f"{'; '.join(answer.risk_reasoning[:3]).lower()}"
        )
    else:
        timeline = "; ".join(answer.context.timeline[:6]) or "No detailed timeline is available."
        techniques = _technique_text(answer.mitre_techniques)
        summary = (
            f"{answer.context.title}: {answer.short_explanation} Timeline: {timeline}. "
            f"MITRE: {techniques}. Investigation should focus on "
            f"{'; '.join(answer.suggested_investigation_steps[:4]).lower()}"
        )
    return CopilotReportResponse(
        report_type=report_type,
        subject_type="incident",
        subject_id=incident_id,
        title=answer.context.title,
        summary=summary,
        evidence_used=answer.evidence_used,
        mitre_techniques=answer.mitre_techniques,
        risk_reasoning=answer.risk_reasoning,
        recommended_actions=answer.suggested_response_actions,
        confidence_score=answer.confidence_score,
        generated_at=datetime.now(timezone.utc),
    )


async def recommend_attack_chain_actions(
    chain_id: str,
    organization_id: str,
) -> CopilotAnswerResponse:
    context = await _attack_chain_context(chain_id, organization_id)
    return _answer_question("What SOAR action should I take?", context)


async def _load_context(request: CopilotQuestionRequest, organization_id: str) -> dict[str, Any]:
    if request.incident_id:
        return await _incident_context(request.incident_id, organization_id)
    if request.attack_chain_id:
        return await _attack_chain_context(request.attack_chain_id, organization_id)
    raise HTTPException(status_code=400, detail="Copilot context is required")


async def _incident_context(incident_id: str, organization_id: str) -> dict[str, Any]:
    incident = await get_incident(incident_id, organization_id)
    alerts = [serialize_document(alert) for alert in incident.get("related_alerts", [])]
    actions = [serialize_document(action) for action in incident.get("soar_actions", [])]
    if not actions:
        actions = await _related_actions(
            organization_id,
            alert_ids=[_string_id(alert) for alert in alerts],
            incident_ids=[incident_id],
        )
    techniques = _normalize_mitre(incident.get("mitre_mappings") or []) or _mitre_from_alerts(alerts)
    assets = _unique(
        [
            *[str(value) for value in incident.get("related_hosts", []) if value],
            *[str(value) for value in incident.get("related_ips", []) if value],
            *[_host(alert) for alert in alerts if _host(alert)],
            *[_user(alert) for alert in alerts if _user(alert)],
        ]
    )
    source_ips = _unique([_source_ip(alert) for alert in alerts if _source_ip(alert)])
    timeline = _incident_timeline(incident, alerts)
    threat_intel = _threat_intel_for_indicators(source_ips)
    risk_score = _incident_risk_score(incident, alerts, threat_intel)
    summary = CopilotContextSummary(
        context_type="incident",
        context_id=incident_id,
        title=incident.get("title") or "Security incident",
        severity=incident.get("severity"),
        status=incident.get("status"),
        risk_score=risk_score,
        alert_count=len(alerts),
        affected_assets=assets,
        source_ips=source_ips,
        timeline=timeline,
        threat_intel=threat_intel,
        soar_actions=_action_labels(actions),
    )
    return {
        "kind": "incident",
        "document": incident,
        "alerts": alerts,
        "actions": actions,
        "techniques": techniques,
        "summary": summary,
    }


async def _attack_chain_context(chain_id: str, organization_id: str) -> dict[str, Any]:
    chain = await get_attack_chain(chain_id, organization_id)
    alert_ids = [str(value) for value in chain.get("related_alert_ids", []) if value]
    incident_ids = [str(value) for value in chain.get("related_incident_ids", []) if value]
    alerts = await _documents_by_ids(alerts_collection, organization_id, alert_ids)
    actions = await _related_actions(organization_id, alert_ids=alert_ids, incident_ids=incident_ids)
    source_ips = _unique(
        [
            *[str(value) for value in chain.get("source_ips", []) if value],
            *[_source_ip(alert) for alert in alerts if _source_ip(alert)],
        ]
    )
    assets = _unique(
        [
            *[str(value) for value in chain.get("affected_hosts", []) if value],
            *[str(value) for value in chain.get("affected_users", []) if value],
            *[_host(alert) for alert in alerts if _host(alert)],
            *[_user(alert) for alert in alerts if _user(alert)],
        ]
    )
    threat_intel = _threat_intel_for_indicators(source_ips)
    techniques = _normalize_mitre(chain.get("mitre_techniques") or []) or _mitre_from_alerts(alerts)
    summary = CopilotContextSummary(
        context_type="attack_chain",
        context_id=chain_id,
        title=chain.get("title") or "Attack chain",
        severity=chain.get("severity"),
        status=chain.get("status"),
        risk_score=_chain_risk_score(chain),
        alert_count=len(alert_ids) or len(alerts),
        affected_assets=assets,
        source_ips=source_ips,
        timeline=_chain_timeline(chain, alerts),
        threat_intel=threat_intel,
        soar_actions=_action_labels(actions),
    )
    return {
        "kind": "attack_chain",
        "document": chain,
        "alerts": alerts,
        "actions": actions,
        "techniques": techniques,
        "summary": summary,
    }


async def _documents_by_ids(collection: Any, organization_id: str, ids: list[str]) -> list[dict[str, Any]]:
    wanted = {str(value) for value in ids if value}
    if not wanted:
        return []
    results = []
    cursor = collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for document in cursor:
        item = serialize_document(document)
        if _string_id(item) in wanted:
            results.append(item)
    return results


async def _related_actions(
    organization_id: str,
    *,
    alert_ids: list[str],
    incident_ids: list[str],
) -> list[dict[str, Any]]:
    alert_set = {str(value) for value in alert_ids if value}
    incident_set = {str(value) for value in incident_ids if value}
    actions = []
    cursor = response_actions_collection.find({"organization_id": organization_id}).sort("timestamp", -1)
    async for action in cursor:
        item = serialize_document(action)
        if str(item.get("alert_id") or "") in alert_set or str(item.get("incident_id") or "") in incident_set:
            actions.append(item)
    return actions


def _answer_question(question: str, context: dict[str, Any]) -> CopilotAnswerResponse:
    normalized = " ".join(question.lower().split())
    summary: CopilotContextSummary = context["summary"]
    risk_reasoning = _risk_reasoning(context)
    investigation_steps = _investigation_steps(context)
    response_actions = _response_actions(context)
    evidence = _evidence(context)
    techniques = context["techniques"]

    if any(term in normalized for term in ("why", "critical", "risk")):
        explanation = _risk_explanation(summary, risk_reasoning)
    elif any(term in normalized for term in ("what happened", "happened", "timeline")):
        explanation = _timeline_explanation(summary)
    elif "mitre" in normalized or "technique" in normalized:
        explanation = f"Mapped ATT&CK coverage: {_technique_text(techniques)}."
    elif "investigate" in normalized or "next" in normalized:
        explanation = f"Next investigation focus: {'; '.join(investigation_steps[:3])}."
    elif "soar" in normalized or "action" in normalized or "respond" in normalized:
        explanation = f"Recommended response: {'; '.join(action.label for action in response_actions[:3])}."
    elif "executive" in normalized:
        explanation = _executive_explanation(summary, risk_reasoning)
    elif "technical" in normalized:
        explanation = _technical_explanation(summary, techniques)
    else:
        explanation = _timeline_explanation(summary)

    return CopilotAnswerResponse(
        context=summary,
        short_explanation=explanation,
        evidence_used=evidence,
        mitre_techniques=techniques,
        risk_reasoning=risk_reasoning,
        suggested_investigation_steps=investigation_steps,
        suggested_response_actions=response_actions,
        confidence_score=_confidence_score(context),
    )


def _risk_explanation(summary: CopilotContextSummary, reasons: list[str]) -> str:
    return (
        f"{summary.title} is {summary.severity or 'unknown'} severity with "
        f"{summary.alert_count} related alert(s). "
        f"The main risk drivers are: {'; '.join(reasons[:4])}."
    )


def _timeline_explanation(summary: CopilotContextSummary) -> str:
    timeline = "; ".join(summary.timeline[:5]) or "No detailed timeline evidence is available."
    return f"What happened: {timeline}"


def _executive_explanation(summary: CopilotContextSummary, reasons: list[str]) -> str:
    assets = ", ".join(summary.affected_assets[:4]) or "unknown assets"
    return (
        f"{summary.title} may affect {assets}. Priority is driven by "
        f"{summary.severity or 'unknown'} severity and {reasons[0].lower() if reasons else 'limited evidence'}."
    )


def _technical_explanation(summary: CopilotContextSummary, techniques: list[dict[str, Any]]) -> str:
    return (
        f"{summary.title} includes {summary.alert_count} alert(s), source IPs "
        f"{', '.join(summary.source_ips[:5]) or 'unknown'}, and MITRE mappings "
        f"{_technique_text(techniques)}."
    )


def _risk_reasoning(context: dict[str, Any]) -> list[str]:
    summary: CopilotContextSummary = context["summary"]
    reasons = []
    severity = _lower(summary.severity)
    if severity in {"critical", "high"}:
        reasons.append(f"{severity.title()} severity indicates potential business impact.")
    if (summary.risk_score or 0) >= 75:
        reasons.append(f"Risk score is elevated at {summary.risk_score:.0f}/100.")
    if summary.alert_count >= 3:
        reasons.append(f"{summary.alert_count} related alerts indicate repeated or chained activity.")
    if context["techniques"]:
        reasons.append("MITRE ATT&CK mapping indicates adversary behavior rather than isolated telemetry.")
    if summary.threat_intel:
        reasons.append("Threat intelligence matched one or more observed indicators.")
    if not reasons:
        reasons.append("Risk is based on available severity, timeline, and asset evidence.")
    return reasons


def _investigation_steps(context: dict[str, Any]) -> list[str]:
    summary: CopilotContextSummary = context["summary"]
    text = _search_text(context)
    steps = [
        "Validate the affected tenant scope, impacted assets, and related alert timeline.",
        "Review endpoint, authentication, and network logs around the first and last observed events.",
    ]
    if "failed login" in text or "brute" in text or _has_technique(context, "T1110"):
        steps.append("Check for password spraying, lockouts, impossible travel, and successful logins after failures.")
    if "powershell" in text or _has_technique(context, "T1059"):
        steps.append("Inspect command line, parent process, script block, and encoded PowerShell evidence.")
    if "credential" in text or "lsass" in text or _has_technique(context, "T1003"):
        steps.append("Look for credential dumping artifacts, LSASS access, and suspicious privilege use.")
    if "lateral" in text or "rdp" in text or "ssh" in text or _has_technique(context, "T1021"):
        steps.append("Scope lateral movement over RDP, SSH, SMB, WinRM, and administrator shares.")
    if summary.threat_intel:
        steps.append("Pivot on matched threat-intel indicators across alerts, logs, and SOAR records.")
    return _unique(steps)


def _response_actions(context: dict[str, Any]) -> list[CopilotSuggestion]:
    summary: CopilotContextSummary = context["summary"]
    text = _search_text(context)
    actions: list[CopilotSuggestion] = []
    priority = _priority(summary.severity, summary.risk_score)
    if summary.source_ips and (summary.threat_intel or "brute" in text or "ddos" in text):
        actions.append(
            CopilotSuggestion(
                action="block_ip",
                label=f"Block or rate-limit {summary.source_ips[0]}",
                rationale="Source IP evidence is present and either threat intelligence or attack-pattern evidence supports containment.",
                priority=priority,
            )
        )
    if summary.affected_assets and _lower(summary.severity) in {"critical", "high"}:
        actions.append(
            CopilotSuggestion(
                action="isolate_host",
                label=f"Isolate or contain {summary.affected_assets[0]} if compromise is confirmed",
                rationale="High-impact asset involvement may require endpoint containment while evidence is preserved.",
                priority=priority,
            )
        )
    actions.append(
        CopilotSuggestion(
            action="run_threat_hunt",
            label="Run a scoped threat hunt",
            rationale="Hunt for the same MITRE techniques, indicators, users, and hosts across the tenant.",
            priority="high" if priority in {"critical", "high"} else "medium",
        )
    )
    if priority == "critical":
        actions.append(
            CopilotSuggestion(
                action="escalate_to_admin",
                label="Escalate to incident command",
                rationale="Critical risk should be reviewed by senior responders before broad containment.",
                priority="critical",
            )
        )
    return _dedupe_suggestions(actions)


def _evidence(context: dict[str, Any]) -> list[str]:
    summary: CopilotContextSummary = context["summary"]
    evidence = [
        f"{summary.context_type.replace('_', ' ').title()} {summary.context_id}: {summary.title}",
        f"Severity/status: {summary.severity or 'unknown'} / {summary.status or 'unknown'}",
        f"Related alerts: {summary.alert_count}",
    ]
    evidence.extend(f"Timeline: {item}" for item in summary.timeline[:5])
    evidence.extend(f"MITRE: {item.get('technique_id')} {item.get('technique_name')}" for item in context["techniques"][:5])
    evidence.extend(f"Threat intel: {item}" for item in summary.threat_intel[:5])
    evidence.extend(f"SOAR: {item}" for item in summary.soar_actions[:5])
    return _unique([item for item in evidence if item.strip()])


def _confidence_score(context: dict[str, Any]) -> float:
    summary: CopilotContextSummary = context["summary"]
    score = 0.35
    score += min(summary.alert_count, 5) * 0.06
    score += min(len(context["techniques"]), 5) * 0.05
    if summary.timeline:
        score += 0.1
    if summary.threat_intel:
        score += 0.08
    if summary.soar_actions:
        score += 0.04
    return round(min(score, 0.95), 2)


def _incident_risk_score(incident: dict[str, Any], alerts: list[dict[str, Any]], threat_intel: list[str]) -> float:
    score = SEVERITY_RISK.get(_lower(incident.get("severity")), 35)
    score += min(len(alerts), 5) * 3
    if threat_intel:
        score += 8
    return float(min(score, 100))


def _chain_risk_score(chain: dict[str, Any]) -> float:
    raw = chain.get("risk_score")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return float(SEVERITY_RISK.get(_lower(chain.get("severity")), 35))
    return min(value * 10 if value <= 10 else value, 100)


def _incident_timeline(incident: dict[str, Any], alerts: list[dict[str, Any]]) -> list[str]:
    events = incident.get("timeline_events") or alerts
    lines = []
    for item in sorted(events, key=lambda event: str(event.get("timestamp") or ""))[:10]:
        label = item.get("message") or item.get("title") or item.get("description") or item.get("event_type")
        parts = [
            _string_or_none(item.get("timestamp")),
            item.get("severity"),
            label,
            _host(item) or item.get("host"),
            _source_ip(item),
        ]
        lines.append(" | ".join(str(part) for part in parts if part))
    if not lines:
        lines.append(incident.get("description") or incident.get("title") or "Incident created")
    return lines


def _chain_timeline(chain: dict[str, Any], alerts: list[dict[str, Any]]) -> list[str]:
    timeline = chain.get("timeline") or alerts
    lines = []
    for item in sorted(timeline, key=lambda event: str(event.get("timestamp") or ""))[:10]:
        label = item.get("message") or item.get("title") or item.get("event_type") or item.get("stage")
        parts = [
            _string_or_none(item.get("timestamp")),
            item.get("stage"),
            item.get("severity"),
            label,
            _host(item),
            _source_ip(item),
        ]
        lines.append(" | ".join(str(part) for part in parts if part))
    return lines


def _mitre_from_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapped = []
    for alert in alerts:
        explicit = _normalize_mitre([alert])
        mapped.extend(explicit or map_alert_to_mitre(alert))
    return _dedupe_mitre(mapped)


def _normalize_mitre(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in items:
        technique_id = item.get("technique_id") or item.get("mitre_technique_id")
        technique_name = item.get("technique_name") or item.get("mitre_technique_name") or item.get("mitre_technique")
        tactic = item.get("tactic") or item.get("tactic_name") or item.get("mitre_tactic_name") or item.get("mitre_tactic")
        tactic_id = item.get("tactic_id") or item.get("mitre_tactic_id")
        if not technique_id and not technique_name and not tactic and not tactic_id:
            continue
        normalized.append(
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic_id": tactic_id,
                "tactic_name": tactic,
                "reason": item.get("reason"),
            }
        )
    return _dedupe_mitre(normalized)


def _dedupe_mitre(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in items:
        key = (item.get("technique_id"), item.get("technique_name"), item.get("tactic_name"))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _threat_intel_for_indicators(indicators: list[str]) -> list[str]:
    results = []
    for indicator in indicators[:10]:
        lookup = lookup_ioc(indicator)
        verdict = lookup.get("verdict")
        if verdict and verdict != "unknown":
            results.append(
                f"{lookup.get('normalized_indicator') or indicator}: {verdict} "
                f"({lookup.get('reputation_score', 0)}/100)"
            )
    return _unique(results)


def _action_labels(actions: list[dict[str, Any]]) -> list[str]:
    labels = []
    for action in actions:
        labels.append(str(action.get("action_type") or action.get("status") or "response_action"))
        labels.extend(str(value) for value in action.get("automated_actions", []) if value)
        labels.extend(f"blocked {value}" for value in action.get("blocked_ips", []) if value)
    return _unique(labels)


def _technique_text(techniques: list[dict[str, Any]]) -> str:
    values = [
        " ".join(str(part) for part in (item.get("technique_id"), item.get("technique_name")) if part)
        for item in techniques
    ]
    return ", ".join(value for value in values if value) or "no mapped techniques"


def _search_text(context: dict[str, Any]) -> str:
    values = []
    for item in [context["document"], *context.get("alerts", [])]:
        values.extend(str(item.get(key) or "") for key in (
            "title",
            "description",
            "message",
            "event_type",
            "severity",
            "stage",
            "mitre_technique",
            "mitre_technique_name",
        ))
    return " ".join(values).lower()


def _has_technique(context: dict[str, Any], technique_id: str) -> bool:
    return any(str(item.get("technique_id") or "").upper() == technique_id for item in context["techniques"])


def _priority(severity: str | None, risk_score: float | None) -> str:
    if _lower(severity) == "critical" or (risk_score or 0) >= 85:
        return "critical"
    if _lower(severity) == "high" or (risk_score or 0) >= 65:
        return "high"
    if _lower(severity) == "medium" or (risk_score or 0) >= 40:
        return "medium"
    return "low"


def _dedupe_suggestions(items: list[CopilotSuggestion]) -> list[CopilotSuggestion]:
    result = []
    seen = set()
    for item in items:
        if item.action in seen:
            continue
        seen.add(item.action)
        result.append(item)
    return result


def _string_id(item: dict[str, Any]) -> str:
    return str(item.get("_id") or item.get("id") or item.get("alert_id") or "")


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _source_ip(item: dict[str, Any]) -> str:
    return str(item.get("source_ip") or item.get("ip_address") or item.get("src_ip") or "")


def _host(item: dict[str, Any]) -> str:
    return str(item.get("hostname") or item.get("host") or item.get("source") or "")


def _user(item: dict[str, Any]) -> str:
    return str(item.get("username") or item.get("user") or item.get("account_name") or "")


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _unique(items: list[str]) -> list[str]:
    return [item for item in dict.fromkeys(item.strip() for item in items if item and item.strip())]
