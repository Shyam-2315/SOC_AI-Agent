from typing import Any, Optional

from pydantic import Field

from app.schemas.base import APIModel


class DetectionPackCreate(APIModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(min_length=1, max_length=4000)
    category: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    enabled: bool = True


class DetectionPackUpdate(APIModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=160)
    description: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    category: Optional[str] = Field(default=None, min_length=1, max_length=120)
    version: Optional[str] = Field(default=None, min_length=1, max_length=40)
    enabled: Optional[bool] = None


class DetectionPackResponse(APIModel):
    id: str
    name: str
    description: str
    category: str
    version: str
    organization_id: str
    rules_count: int
    enabled: bool
    created_by: str
    created_at: Any
    updated_at: Any
