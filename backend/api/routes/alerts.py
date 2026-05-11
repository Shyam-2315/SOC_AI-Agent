from fastapi import APIRouter, Depends

from core.database import alerts_collection
from core.dependencies import Pagination, get_current_user, pagination_params


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


@router.get("/")
async def get_alerts(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    alerts = []
    cursor = (
        alerts_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for alert in cursor:
        alert["_id"] = str(alert["_id"])
        alerts.append(alert)

    total = await alerts_collection.count_documents(query)

    return {
        "items": alerts,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }
