from typing import Literal, Optional

from pydantic import Field, field_validator

from app.schemas.base import APIModel


class IncidentCreate(APIModel):
    title: str = Field(min_length=1, max_length=180)
    description: str = Field(min_length=1, max_length=4000)
    severity: str = Field(min_length=1, max_length=20)
    assigned_to: Optional[str] = Field(default=None, max_length=120)
    assigned_to_user_id: Optional[str] = Field(default=None, max_length=64)
    assigned_to_email: Optional[str] = Field(default=None, max_length=180)
    investigation_notes: Optional[str] = Field(default=None, max_length=8000)

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        return value.lower()


class IncidentUpdate(APIModel):
    status: Optional[
        Literal["new", "investigating", "contained", "resolved", "false_positive", "open", "closed"]
    ] = None
    assigned_to_user_id: Optional[str] = Field(default=None, max_length=64)
    assigned_to_email: Optional[str] = Field(default=None, max_length=180)
    investigation_notes: Optional[str] = Field(default=None, max_length=8000)

    @field_validator("status", "assigned_to_email")
    @classmethod
    def normalize_status(cls, value: Optional[str]) -> Optional[str]:
        return value.lower() if value else value
