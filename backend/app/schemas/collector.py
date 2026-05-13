from typing import Any, Literal, Optional

from pydantic import Field, field_validator

from app.schemas.base import APIModel


CollectorType = Literal["linux", "windows", "syslog", "firewall", "cloud", "custom"]
CollectorStatus = Literal["active", "disabled"]


class CollectorCreate(APIModel):
    name: str = Field(min_length=2, max_length=160)
    type: CollectorType
    status: CollectorStatus = "active"

    @field_validator("type", "status")
    @classmethod
    def normalize_lowercase(cls, value: str) -> str:
        return value.lower()


class CollectorUpdate(APIModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=160)
    type: Optional[CollectorType] = None
    status: Optional[CollectorStatus] = None

    @field_validator("type", "status")
    @classmethod
    def normalize_optional_lowercase(cls, value: Optional[str]) -> Optional[str]:
        return value.lower() if value else value


class CollectorResponse(APIModel):
    id: str
    name: str
    type: CollectorType
    organization_id: str
    status: CollectorStatus
    last_seen_at: Optional[Any] = None
    created_at: Any
    updated_at: Any


class CollectorIngestBatch(APIModel):
    logs: list[dict[str, Any]] = Field(min_length=1)
