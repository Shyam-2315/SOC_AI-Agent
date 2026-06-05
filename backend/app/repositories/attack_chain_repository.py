from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from app.common.mongo import parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.db.client import attack_chains_collection


def _serialize_attack_chain(document: dict[str, Any]) -> dict[str, Any]:
    serialized = serialize_document(document)
    serialized["id"] = str(serialized.get("_id") or serialized.get("id"))
    serialized.pop("_id", None)
    return serialized


async def create_attack_chain(organization_id: str, chain: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document = {
        **chain,
        "organization_id": organization_id,
        "created_at": now,
        "updated_at": now,
    }
    result = await attack_chains_collection.insert_one(document)
    document["_id"] = result.inserted_id
    return _serialize_attack_chain(document)


async def list_attack_chains(organization_id: str, pagination: Pagination) -> dict[str, Any]:
    items = []
    cursor = (
        attack_chains_collection.find({"organization_id": organization_id})
        .sort("updated_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for chain in cursor:
        items.append(_serialize_attack_chain(chain))
    total = await attack_chains_collection.count_documents({"organization_id": organization_id})
    return {
        "items": items,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


async def get_attack_chain(chain_id: str, organization_id: str) -> dict[str, Any]:
    object_id = parse_object_id(chain_id, "attack chain")
    chain = await attack_chains_collection.find_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return _serialize_attack_chain(chain)


async def update_attack_chain(chain_id: str, organization_id: str, update: dict[str, Any]) -> dict[str, Any]:
    object_id = parse_object_id(chain_id, "attack chain")
    update = {**update, "updated_at": datetime.now(timezone.utc)}
    result = await attack_chains_collection.update_one(
        {"_id": object_id, "organization_id": organization_id},
        {"$set": update},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return await get_attack_chain(chain_id, organization_id)


async def update_attack_chain_status(
    chain_id: str,
    organization_id: str,
    status: str,
) -> dict[str, Any]:
    return await update_attack_chain(chain_id, organization_id, {"status": status})


async def delete_attack_chain(chain_id: str, organization_id: str) -> dict[str, str]:
    object_id = parse_object_id(chain_id, "attack chain")
    result = await attack_chains_collection.delete_one(
        {"_id": object_id, "organization_id": organization_id}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    return {"message": "Attack chain deleted"}


async def find_existing_chain_for_alert_group(
    organization_id: str,
    alert_ids: list[str],
) -> dict[str, Any] | None:
    if not alert_ids:
        return None
    chain = await attack_chains_collection.find_one(
        {
            "organization_id": organization_id,
            "related_alert_ids": {"$in": alert_ids},
            "status": {"$in": ["open", "investigating", "contained"]},
        }
    )
    return _serialize_attack_chain(chain) if chain else None
