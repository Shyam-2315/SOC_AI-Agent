from datetime import datetime, timezone
from typing import Any

from app.schemas.reports import IncidentReport, ReportSection, ReportType
from app.services.ai_copilot_service import (
    recommend_actions_for_incident,
    summarize_incident,
)
from app.services.incidents import get_incident
from app.services.threat_intel_service import enrich_incident_threat_intel


async def generate_incident_report(
    incident_id: str,
    report_type: ReportType,
    organization_id: str,
) -> IncidentReport:
    if report_type == "executive":
        return await generate_executive_report(incident_id, organization_id)
    if report_type == "technical":
        return await generate_technical_report(incident_id, organization_id)
    if report_type == "compliance":
        return await generate_compliance_report(incident_id, organization_id)
    raise ValueError(f"Unsupported report type: {report_type}")


async def generate_executive_report(
    incident_id: str,
    organization_id: str,
) -> IncidentReport:
    context = await _build_report_context(incident_id, organization_id)
    sections = [
        ReportSection(
            title="Business Impact",
            summary=_impact_summary(context),
            items=[
                f"Severity: {context['severity']}",
                f"Affected assets: {len(context['affected_assets'])}",
                f"Matched IOCs: {len(context['matched_iocs'])}",
            ],
        ),
        ReportSection(
            title="Recommended Response",
            summary="Priority response actions for leadership tracking.",
            items=context["recommended_actions"],
        ),
    ]
    return _build_report(context, "executive", sections)


async def generate_technical_report(
    incident_id: str,
    organization_id: str,
) -> IncidentReport:
    context = await _build_report_context(incident_id, organization_id)
    sections = [
        ReportSection(
            title="Technical Timeline",
            summary="Observed incident and alert activity in deterministic timestamp order.",
            data={"events": context["timeline"]},
        ),
        ReportSection(
            title="Detection Evidence",
            summary="Mapped ATT&CK techniques and matched threat indicators.",
            data={
                "mitre_techniques": context["mitre_techniques"],
                "matched_iocs": context["matched_iocs"],
                "related_alerts": context["incident"].get("related_alerts", []),
            },
        ),
        ReportSection(
            title="SOAR Activity",
            summary="Automated or simulated response actions associated with this incident.",
            data={"actions": context["soar_actions"]},
        ),
    ]
    return _build_report(context, "technical", sections)


async def generate_compliance_report(
    incident_id: str,
    organization_id: str,
) -> IncidentReport:
    context = await _build_report_context(incident_id, organization_id)
    sections = [
        ReportSection(
            title="Incident Record",
            summary="Core incident facts for audit and retention workflows.",
            items=[
                f"Incident ID: {context['incident_id']}",
                f"Status: {context['incident'].get('status') or 'unknown'}",
                f"Severity: {context['severity']}",
            ],
            data={
                "created_at": context["incident"].get("timestamp")
                or context["incident"].get("created_at"),
                "assigned_to": context["incident"].get("assigned_to_email")
                or context["incident"].get("assigned_to"),
            },
        ),
        ReportSection(
            title="Evidence Summary",
            summary="Security evidence retained for compliance review.",
            data={
                "timeline": context["timeline"],
                "mitre_techniques": context["mitre_techniques"],
                "matched_iocs": context["matched_iocs"],
                "soar_actions": context["soar_actions"],
            },
        ),
        ReportSection(
            title="Remediation Tracking",
            summary="Actions recommended or taken to reduce recurrence risk.",
            items=context["recommended_actions"],
        ),
    ]
    return _build_report(context, "compliance", sections)


async def _build_report_context(incident_id: str, organization_id: str) -> dict[str, Any]:
    incident = await get_incident(incident_id, organization_id)
    threat_intel = await enrich_incident_threat_intel(incident_id, organization_id)
    copilot_summary = await summarize_incident(incident_id, organization_id)
    copilot_actions = await recommend_actions_for_incident(incident_id, organization_id)

    affected_assets = _unique_strings(
        [
            *incident.get("related_hosts", []),
            *incident.get("related_ips", []),
            *threat_intel.get("affected_assets", []),
            *copilot_summary.get("affected_assets", []),
        ]
    )
    recommended_actions = _unique_strings(
        [
            *copilot_actions.get("recommended_actions", []),
            *copilot_summary.get("recommended_actions", []),
            *threat_intel.get("recommended_actions", []),
        ]
    )
    if not recommended_actions:
        recommended_actions = _fallback_actions(incident)

    timeline = incident.get("timeline_events") or copilot_summary.get("attack_timeline") or []
    mitre_techniques = (
        incident.get("mitre_mappings") or copilot_summary.get("mitre_techniques") or []
    )

    return {
        "incident": incident,
        "incident_id": str(incident.get("_id") or incident_id),
        "title": incident.get("title") or copilot_summary.get("title") or "Security incident",
        "executive_summary": copilot_summary.get("executive_summary")
        or incident.get("investigation_summary")
        or "Security incident report generated from available deterministic evidence.",
        "severity": str(incident.get("severity") or "unknown"),
        "affected_assets": affected_assets,
        "timeline": timeline,
        "mitre_techniques": mitre_techniques,
        "matched_iocs": threat_intel.get("matched_indicators", []),
        "recommended_actions": recommended_actions,
        "soar_actions": incident.get("soar_actions", []),
        "analyst_notes": incident.get("notes")
        or incident.get("investigation_notes")
        or "",
    }


def _build_report(
    context: dict[str, Any],
    report_type: ReportType,
    sections: list[ReportSection],
) -> IncidentReport:
    return IncidentReport(
        incident_id=context["incident_id"],
        report_type=report_type,
        title=f"{context['title']} - {report_type.title()} Incident Report",
        generated_at=datetime.now(timezone.utc),
        executive_summary=context["executive_summary"],
        severity=context["severity"],
        affected_assets=context["affected_assets"],
        timeline=context["timeline"],
        mitre_techniques=context["mitre_techniques"],
        matched_iocs=context["matched_iocs"],
        recommended_actions=context["recommended_actions"],
        soar_actions=context["soar_actions"],
        analyst_notes=context["analyst_notes"],
        sections=sections,
    )


def _impact_summary(context: dict[str, Any]) -> str:
    assets = context["affected_assets"]
    asset_text = ", ".join(assets[:5]) if assets else "no confirmed assets"
    return (
        f"{context['severity'].title()} incident affecting {asset_text}; "
        f"{len(context['recommended_actions'])} response action(s) are recommended."
    )


def _fallback_actions(incident: dict[str, Any]) -> list[str]:
    severity = str(incident.get("severity") or "").lower()
    if severity in {"critical", "high"}:
        return ["open_investigation", "run_threat_hunt"]
    return ["monitor_only"]


def _unique_strings(values: list[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))
