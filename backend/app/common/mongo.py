from typing import Any

from bson import ObjectId
from fastapi import HTTPException

from app.common.pagination import Pagination


def parse_object_id(value: str, resource_name: str) -> ObjectId:
    try:
        return ObjectId(value)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {resource_name} id",
        ) from exc


def serialize_document(document: dict[str, Any]) -> dict[str, Any]:
    serialized = dict(document)
    if "_id" in serialized:
        serialized["_id"] = str(serialized["_id"])
    return serialized


def paginated_response(
    items: list[dict[str, Any]],
    total: int,
    pagination: Pagination,
) -> dict[str, Any]:
    return {
        "items": items,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }
