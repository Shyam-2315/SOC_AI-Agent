from pydantic import BaseModel


class IncidentCreate(BaseModel):

    title: str
    description: str
    severity: str
    assigned_to: str


class IncidentUpdate(BaseModel):

    status: str