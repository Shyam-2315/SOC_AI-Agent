from fastapi import APIRouter, Depends, Query

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.services.soar import get_playbook, list_blocked_ips, list_response_actions


router = APIRouter(
    prefix="/soar",
    tags=["SOAR"],
)


@router.get("/actions")
async def get_response_actions(
    incident_id: str | None = Query(default=None),
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("soar:read")),
):
    return await list_response_actions(user["organization_id"], pagination, incident_id)


@router.get("/blocked-ips")
async def get_blocked_ips(
    user=Depends(require_permission("soar:read")),
):
    return await list_blocked_ips(user["organization_id"])


@router.get("/playbook/{event_type}")
async def get_playbook_endpoint(
    event_type: str,
    user=Depends(require_permission("soar:read")),
):
    return get_playbook(event_type)
