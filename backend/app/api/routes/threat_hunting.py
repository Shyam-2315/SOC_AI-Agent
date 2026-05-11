from fastapi import APIRouter, Depends

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.services.threat_hunting import (
    attack_timeline,
    detect_campaigns,
    threat_statistics,
)


router = APIRouter(
    prefix="/threat-hunting",
    tags=["Threat Hunting"],
)


@router.get("/campaigns")
async def detect_campaigns_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("threat_hunting:read")),
):
    return await detect_campaigns(user["organization_id"], pagination)


@router.get("/timeline")
async def attack_timeline_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("threat_hunting:read")),
):
    return await attack_timeline(user["organization_id"], pagination)


@router.get("/statistics")
async def threat_statistics_endpoint(
    user=Depends(require_permission("threat_hunting:read")),
):
    return await threat_statistics(user["organization_id"])
