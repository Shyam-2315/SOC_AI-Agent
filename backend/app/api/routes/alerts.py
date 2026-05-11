from fastapi import APIRouter, Depends

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.services.alerts import list_alerts


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


@router.get("/")
async def get_alerts(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("alerts:read")),
):
    return await list_alerts(user["organization_id"], pagination)
