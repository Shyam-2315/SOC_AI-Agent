from ipaddress import IPv4Address, IPv6Address
from datetime import datetime
from typing import Any, Optional, Union

from pydantic import Field, field_validator

from app.schemas.base import APIModel


class LogModel(APIModel):
    source: str = Field(min_length=1, max_length=120)
    event_type: str = Field(min_length=1, max_length=80)
    severity: str = Field(min_length=1, max_length=20)
    message: str = Field(min_length=1, max_length=4000)
    ip_address: Union[IPv4Address, IPv6Address]
    organization_id: Optional[str] = Field(default=None, exclude=True)
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = Field(default=None, max_length=255)
    host: Optional[str] = Field(default=None, max_length=255)
    event_id: Optional[int] = None
    provider: Optional[str] = Field(default=None, max_length=255)
    record_id: Optional[int] = None
    logon_type: Optional[str] = Field(default=None, max_length=80)
    username: Optional[str] = Field(default=None, max_length=255)
    domain: Optional[str] = Field(default=None, max_length=255)
    source_ip: Optional[str] = Field(default=None, max_length=255)
    workstation_name: Optional[str] = Field(default=None, max_length=255)
    failure_reason: Optional[str] = Field(default=None, max_length=1000)
    status: Optional[str] = Field(default=None, max_length=80)
    substatus: Optional[str] = Field(default=None, max_length=80)
    process_name: Optional[str] = Field(default=None, max_length=1000)
    raw_event: Optional[dict[str, Any]] = None

    @field_validator("event_type", "severity")
    @classmethod
    def normalize_lowercase_fields(cls, value: str) -> str:
        return value.lower()
