from typing import Optional

from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    description: str = Field(min_length=1, max_length=4000)
    severity: str = Field(min_length=1, max_length=20)
    assigned_to: Optional[str] = Field(default=None, max_length=120)


class IncidentUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=40)
