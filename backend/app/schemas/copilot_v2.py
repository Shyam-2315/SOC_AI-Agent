from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from app.schemas.base import APIModel


CopilotContextType = Literal["incident", "attack_chain"]
CopilotReportType = Literal["executive", "technical"]


class CopilotQuestionRequest(APIModel):
    question: str = Field(min_length=1, max_length=1000)
    incident_id: str | None = Field(default=None, max_length=64)
    attack_chain_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def require_single_context(self):
        if bool(self.incident_id) == bool(self.attack_chain_id):
            raise ValueError("Provide exactly one of incident_id or attack_chain_id")
        return self


class CopilotSuggestion(APIModel):
    action: str = Field(min_length=1, max_length=120)
    label: str = Field(min_length=1, max_length=220)
    rationale: str = Field(min_length=1, max_length=800)
    priority: Literal["low", "medium", "high", "critical"] = "medium"


class CopilotContextSummary(APIModel):
    context_type: CopilotContextType
    context_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=220)
    severity: str | None = Field(default=None, max_length=20)
    status: str | None = Field(default=None, max_length=40)
    risk_score: float | None = Field(default=None, ge=0, le=100)
    alert_count: int = Field(default=0, ge=0)
    affected_assets: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)
    threat_intel: list[str] = Field(default_factory=list)
    soar_actions: list[str] = Field(default_factory=list)


class CopilotAnswerResponse(APIModel):
    context: CopilotContextSummary
    short_explanation: str = Field(min_length=1, max_length=4000)
    evidence_used: list[str] = Field(default_factory=list)
    mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    risk_reasoning: list[str] = Field(default_factory=list)
    suggested_investigation_steps: list[str] = Field(default_factory=list)
    suggested_response_actions: list[CopilotSuggestion] = Field(default_factory=list)
    confidence_score: float = Field(ge=0, le=1)


class CopilotReportResponse(APIModel):
    report_type: CopilotReportType
    subject_type: CopilotContextType
    subject_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=220)
    summary: str = Field(min_length=1, max_length=8000)
    evidence_used: list[str] = Field(default_factory=list)
    mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    risk_reasoning: list[str] = Field(default_factory=list)
    recommended_actions: list[CopilotSuggestion] = Field(default_factory=list)
    confidence_score: float = Field(ge=0, le=1)
    generated_at: datetime
