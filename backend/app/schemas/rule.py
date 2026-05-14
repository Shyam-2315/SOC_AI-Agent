from typing import Any, Literal, Optional

from pydantic import Field, field_validator

from app.schemas.base import APIModel


RuleOperator = Literal["equals", "contains"]
RuleField = Literal["source", "event_type", "severity", "message", "ip_address"]


class RuleCondition(APIModel):
    field: RuleField
    operator: RuleOperator = "equals"
    value: str = Field(min_length=1, max_length=1000)

    @field_validator("field", "operator")
    @classmethod
    def normalize_lowercase(cls, value: str) -> str:
        return value.lower()


class DetectionRuleCreate(APIModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(min_length=1, max_length=4000)
    severity: str = Field(min_length=1, max_length=20)
    event_type: Optional[str] = Field(default=None, min_length=1, max_length=80)
    conditions: list[RuleCondition] = Field(min_length=1, max_length=20)
    mitre_tactic: Optional[str] = Field(default=None, max_length=120)
    mitre_technique: Optional[str] = Field(default=None, max_length=180)
    mitre_tactic_id: Optional[str] = Field(default=None, max_length=20)
    mitre_tactic_name: Optional[str] = Field(default=None, max_length=120)
    mitre_technique_id: Optional[str] = Field(default=None, max_length=20)
    mitre_technique_name: Optional[str] = Field(default=None, max_length=180)
    mitre_subtechnique_id: Optional[str] = Field(default=None, max_length=30)
    mitre_subtechnique_name: Optional[str] = Field(default=None, max_length=180)
    pack_id: Optional[str] = Field(default=None, max_length=64)
    enabled: bool = True

    @field_validator("severity", "event_type")
    @classmethod
    def normalize_optional_lowercase(cls, value: Optional[str]) -> Optional[str]:
        return value.lower() if value else value


class DetectionRuleUpdate(APIModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    severity: Optional[str] = Field(default=None, min_length=1, max_length=20)
    event_type: Optional[str] = Field(default=None, min_length=1, max_length=80)
    conditions: Optional[list[RuleCondition]] = Field(default=None, min_length=1, max_length=20)
    mitre_tactic: Optional[str] = Field(default=None, max_length=120)
    mitre_technique: Optional[str] = Field(default=None, max_length=180)
    mitre_tactic_id: Optional[str] = Field(default=None, max_length=20)
    mitre_tactic_name: Optional[str] = Field(default=None, max_length=120)
    mitre_technique_id: Optional[str] = Field(default=None, max_length=20)
    mitre_technique_name: Optional[str] = Field(default=None, max_length=180)
    mitre_subtechnique_id: Optional[str] = Field(default=None, max_length=30)
    mitre_subtechnique_name: Optional[str] = Field(default=None, max_length=180)
    pack_id: Optional[str] = Field(default=None, max_length=64)
    enabled: Optional[bool] = None

    @field_validator("severity", "event_type")
    @classmethod
    def normalize_update_lowercase(cls, value: Optional[str]) -> Optional[str]:
        return value.lower() if value else value


class DetectionRuleResponse(APIModel):
    id: str
    name: str
    description: str
    severity: str
    event_type: Optional[str] = None
    conditions: list[dict[str, Any]]
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_tactic_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_subtechnique_id: Optional[str] = None
    mitre_subtechnique_name: Optional[str] = None
    pack_id: Optional[str] = None
    enabled: bool
    organization_id: str
    created_by: str
    created_at: Any
    updated_at: Any
