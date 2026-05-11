from app.common.mongo import paginated_response, serialize_document
from app.common.pagination import Pagination
from app.db.client import alerts_collection


async def list_alerts(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        alerts_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for alert in cursor:
        items.append(serialize_document(alert))

    total = await alerts_collection.count_documents(query)
    return paginated_response(items, total, pagination)
