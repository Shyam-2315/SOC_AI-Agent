from typing import Any, Literal

from pydantic import Field, field_validator

from app.schemas.base import APIModel


class AttackGraphNode(APIModel):
    id: str = Field(min_length=1, max_length=180)
    type: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=200)
    severity: str | None = Field(default=None, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str | None) -> str | None:
        return value.lower() if value else value


class AttackGraphEdge(APIModel):
    source: str = Field(min_length=1, max_length=180)
    target: str = Field(min_length=1, max_length=180)
    label: Literal[
        "attacked",
        "targeted",
        "attempted",
        "triggered",
        "correlated",
        "response",
        "mapped to",
        "observed on",
        "related",
    ]


class AttackGraphResponse(APIModel):
    incident_id: str
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
