from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

from pydantic import Field, field_validator

from app.schemas.base import APIModel


class LogModel(APIModel):
    source: str = Field(min_length=1, max_length=120)
    event_type: str = Field(min_length=1, max_length=80)
    severity: str = Field(min_length=1, max_length=20)
    message: str = Field(min_length=1, max_length=4000)
    ip_address: Union[IPv4Address, IPv6Address]
    organization_id: Optional[str] = Field(default=None, exclude=True)

    @field_validator("event_type", "severity")
    @classmethod
    def normalize_lowercase_fields(cls, value: str) -> str:
        return value.lower()
