from fastapi import APIRouter, Depends

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services.incidents import (
    create_incident,
    get_incident,
    list_incidents,
    update_incident_status,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


@router.post("/")
async def create_incident_endpoint(
    incident: IncidentCreate,
    user=Depends(require_permission("incidents:write")),
):
    return await create_incident(incident, user)


@router.get("/")
async def get_incidents(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("incidents:read")),
):
    return await list_incidents(user["organization_id"], pagination)


@router.get("/{incident_id}")
async def get_incident_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    return await get_incident(incident_id, user["organization_id"])


@router.patch("/{incident_id}")
async def update_incident_status_endpoint(
    incident_id: str,
    update: IncidentUpdate,
    user=Depends(require_permission("incidents:write")),
):
    return await update_incident_status(incident_id, update, user)
