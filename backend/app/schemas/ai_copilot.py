from typing import Any, Literal

from pydantic import Field

from app.schemas.base import APIModel


Priority = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
SuggestedStatus = Literal["investigate", "monitor", "likely_false_positive"]
RecommendedAction = Literal[
    "block_ip",
    "isolate_host",
    "escalate_to_admin",
    "monitor_only",
    "close_false_positive",
    "open_investigation",
    "run_threat_hunt",
]


class MitreTechnique(APIModel):
    tactic_id: str | None = None
    tactic_name: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    subtechnique_id: str | None = None
    subtechnique_name: str | None = None


class AlertTriageResponse(APIModel):
    alert_id: str
    risk_score: int = Field(ge=0, le=100)
    priority: Priority
    reasoning: list[str]
    recommended_action: RecommendedAction
    mapped_mitre_techniques: list[MitreTechnique]


class IncidentTimelineItem(APIModel):
    timestamp: str | None = None
    event_type: str | None = None
    description: str
    severity: str | None = None
    source_ip: str | None = None
    host: str | None = None


class IncidentSummaryResponse(APIModel):
    incident_id: str
    title: str
    executive_summary: str
    root_cause_guess: str
    affected_assets: list[str]
    attack_timeline: list[IncidentTimelineItem]
    mitre_techniques: list[MitreTechnique]
    recommended_actions: list[RecommendedAction]
    analyst_next_steps: list[str]


class FalsePositiveScoreResponse(APIModel):
    alert_id: str
    false_positive_score: int = Field(ge=0, le=100)
    confidence: Confidence
    reasons: list[str]
    suggested_status: SuggestedStatus


class RecommendedActionsResponse(APIModel):
    incident_id: str
    recommended_actions: list[RecommendedAction]
    reasons: list[str]


class CopilotQueryRequest(APIModel):
    query: str = Field(min_length=1, max_length=2000)


class CopilotQueryResponse(APIModel):
    intent: str
    filters: dict[str, Any]
    backend_endpoint_suggestion: str
    explanation: str
    result_preview: dict[str, Any] | None = None
