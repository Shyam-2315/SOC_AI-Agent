from app.common.mongo import paginated_response, serialize_document
from app.common.pagination import Pagination
from app.db.client import logs_collection


async def list_logs(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        logs_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for log in cursor:
        items.append(serialize_document(log))

    total = await logs_collection.count_documents(query)
    return paginated_response(items, total, pagination)
