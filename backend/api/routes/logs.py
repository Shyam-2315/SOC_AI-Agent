from fastapi import APIRouter, Depends

from core.database import logs_collection
from core.dependencies import Pagination, get_current_user, pagination_params


router = APIRouter(
    prefix="/logs",
    tags=["Logs"],
)


@router.get("/")
async def get_logs(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    logs = []
    cursor = (
        logs_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for log in cursor:
        log["_id"] = str(log["_id"])
        logs.append(log)

    total = await logs_collection.count_documents(query)

    return {
        "items": logs,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }
