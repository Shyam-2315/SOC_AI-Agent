from pydantic import Field

from app.schemas.base import APIModel


class OrganizationCreate(APIModel):
    name: str = Field(min_length=2, max_length=120)


class OrganizationResponse(APIModel):
    id: str
    name: str
