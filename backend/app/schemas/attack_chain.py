from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from app.schemas.base import APIModel


AttackChainStatus = Literal["open", "investigating", "contained", "resolved"]
AttackChainSeverity = Literal["low", "medium", "high", "critical"]


class MitreTechnique(APIModel):
    technique_id: str = Field(min_length=1, max_length=32)
    technique_name: str = Field(min_length=1, max_length=160)
    tactic: str = Field(min_length=1, max_length=80)
    reason: str = Field(min_length=1, max_length=500)


class AttackTimelineItem(APIModel):
    alert_id: str | None = Field(default=None, max_length=64)
    timestamp: datetime | None = None
    title: str | None = Field(default=None, max_length=220)
    event_type: str | None = Field(default=None, max_length=120)
    severity: str | None = Field(default=None, max_length=20)
    host: str | None = Field(default=None, max_length=180)
    user: str | None = Field(default=None, max_length=180)
    source_ip: str | None = Field(default=None, max_length=80)
    destination_ip: str | None = Field(default=None, max_length=80)
    process_name: str | None = Field(default=None, max_length=180)
    stage: str | None = Field(default=None, max_length=80)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    message: str | None = Field(default=None, max_length=2000)

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str | None) -> str | None:
        return value.lower() if value else value


class AttackChainCreate(APIModel):
    title: str = Field(min_length=1, max_length=220)
    status: AttackChainStatus = "open"
    severity: AttackChainSeverity
    risk_score: float = Field(ge=0, le=10)
    confidence_score: float = Field(ge=0, le=1)
    related_alert_ids: list[str] = Field(default_factory=list)
    related_incident_ids: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    attack_stages: list[str] = Field(default_factory=list)
    timeline: list[AttackTimelineItem] = Field(default_factory=list)
    ai_summary: str = Field(min_length=1, max_length=6000)
    recommended_actions: list[str] = Field(default_factory=list)


class AttackChainRead(AttackChainCreate):
    id: str
    organization_id: str
    created_at: datetime
    updated_at: datetime


class AttackChainListItem(APIModel):
    id: str
    organization_id: str
    title: str
    status: AttackChainStatus
    severity: AttackChainSeverity
    risk_score: float = Field(ge=0, le=10)
    confidence_score: float = Field(ge=0, le=1)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    attack_stages: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    related_incident_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AttackChainStatusUpdate(APIModel):
    status: AttackChainStatus


class AttackGraphNode(APIModel):
    id: str = Field(min_length=1, max_length=180)
    type: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=220)
    severity: str | None = Field(default=None, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackGraphEdge(APIModel):
    id: str = Field(min_length=1, max_length=220)
    source: str = Field(min_length=1, max_length=180)
    target: str = Field(min_length=1, max_length=180)
    label: str = Field(min_length=1, max_length=80)


class AttackGraphResponse(APIModel):
    chain_id: str
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
