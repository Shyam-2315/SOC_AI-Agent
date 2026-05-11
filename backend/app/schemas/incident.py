from typing import Optional

from pydantic import Field, field_validator

from app.schemas.base import APIModel


class IncidentCreate(APIModel):
    title: str = Field(min_length=1, max_length=180)
    description: str = Field(min_length=1, max_length=4000)
    severity: str = Field(min_length=1, max_length=20)
    assigned_to: Optional[str] = Field(default=None, max_length=120)

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        return value.lower()


class IncidentUpdate(APIModel):
    status: str = Field(min_length=1, max_length=40)

    @field_validator("status")
    @classmethod
    def normalize_status(cls, value: str) -> str:
        return value.lower()
