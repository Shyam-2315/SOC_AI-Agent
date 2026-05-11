from fastapi import APIRouter, Depends

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.services.logs import list_logs


router = APIRouter(
    prefix="/logs",
    tags=["Logs"],
)


@router.get("/")
async def get_logs(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("logs:read")),
):
    return await list_logs(user["organization_id"], pagination)
