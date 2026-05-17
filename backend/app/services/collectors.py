from datetime import datetime, timezone
import hashlib
import secrets
from typing import Any

from fastapi import HTTPException, status
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.core.config import settings
from app.db.client import collectors_collection
from app.schemas.collector import CollectorCreate, CollectorIngestBatch, CollectorUpdate
from app.schemas.log import LogModel
from app.services.audit import write_audit_event
from app.services.ingestion import ingest_log


def hash_collector_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_collector_token() -> str:
    return f"soc_col_{secrets.token_urlsafe(32)}"


def _serialize_collector(collector: dict[str, Any]) -> dict[str, Any]:
    serialized = serialize_document(collector)
    serialized["id"] = serialized.pop("_id")
    serialized.pop("api_key_hash", None)
    return serialized


async def create_collector(data: CollectorCreate, user: dict) -> dict:
    now = datetime.now(timezone.utc)
    token = _generate_collector_token()
    document = {
        "name": data.name,
        "type": data.type,
        "organization_id": user["organization_id"],
        "api_key_hash": hash_collector_token(token),
        "status": data.status,
        "last_seen_at": None,
        "created_at": now,
        "updated_at": now,
    }
    try:
        result = await collectors_collection.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="Collector name already exists for this organization",
        ) from exc

    document["_id"] = result.inserted_id
    await write_audit_event(
        event_type="collector.created",
        actor=user,
        target_type="collector",
        target_id=str(result.inserted_id),
        metadata={"name": data.name, "type": data.type, "status": data.status},
    )
    return {
        "message": "Collector created",
        "collector": _serialize_collector(document),
        "api_key": token,
    }


async def list_collectors(organization_id: str, pagination: Pagination) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        collectors_collection.find(query)
        .sort("created_at", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for collector in cursor:
        items.append(_serialize_collector(collector))
    total = await collectors_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def update_collector(
    collector_id: str,
    update: CollectorUpdate,
    user: dict,
) -> dict:
    object_id = parse_object_id(collector_id, "collector")
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    update_data["updated_at"] = datetime.now(timezone.utc)

    try:
        result = await collectors_collection.update_one(
            {"_id": object_id, "organization_id": user["organization_id"]},
            {"$set": update_data},
        )
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=400,
            detail="Collector name already exists for this organization",
        ) from exc

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Collector not found")

    event_type = (
        "collector.disabled"
        if update_data.get("status") == "disabled"
        else "collector.updated"
    )
    await write_audit_event(
        event_type=event_type,
        actor=user,
        target_type="collector",
        target_id=collector_id,
        metadata={"fields": sorted(update_data.keys())},
    )
    collector = await collectors_collection.find_one(
        {"_id": object_id, "organization_id": user["organization_id"]}
    )
    return {"message": "Collector updated", "collector": _serialize_collector(collector)}


async def delete_collector(collector_id: str, user: dict) -> dict:
    object_id = parse_object_id(collector_id, "collector")
    result = await collectors_collection.delete_one(
        {"_id": object_id, "organization_id": user["organization_id"]}
    )
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Collector not found")

    await write_audit_event(
        event_type="collector.deleted",
        actor=user,
        organization_id=user["organization_id"],
        target_type="collector",
        target_id=collector_id,
    )
    return {"message": "Collector deleted"}


async def authenticate_collector_token(token: str | None) -> dict:
    if not token:
        await write_audit_event(
            event_type="collector.ingestion_auth_failure",
            outcome="failure",
            metadata={"reason": "missing_token"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Collector token is required",
        )

    for configured_token, organization_id in getattr(settings, "collector_api_keys", {}).items():
        if secrets.compare_digest(token, configured_token):
            return {
                "_id": f"env:{organization_id}",
                "name": "Environment collector token",
                "type": "custom",
                "organization_id": organization_id,
                "status": "active",
                "env_configured": True,
            }

    collector = await collectors_collection.find_one(
        {"api_key_hash": hash_collector_token(token)}
    )
    if not collector:
        await write_audit_event(
            event_type="collector.ingestion_auth_failure",
            outcome="failure",
            metadata={"reason": "invalid_token"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid collector token",
        )

    if collector.get("status") != "active":
        await write_audit_event(
            event_type="collector.ingestion_auth_failure",
            organization_id=collector.get("organization_id"),
            target_type="collector",
            target_id=str(collector["_id"]),
            outcome="failure",
            metadata={"reason": "collector_disabled"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Collector is disabled",
        )

    return collector


async def ingest_collector_batch(batch: CollectorIngestBatch, collector: dict) -> dict:
    if len(batch.logs) > settings.collector_batch_max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Collector batch size cannot exceed {settings.collector_batch_max_size}",
        )

    accepted = 0
    rejected = 0
    results = []
    errors = []
    organization_id = collector["organization_id"]

    for index, raw_log in enumerate(batch.logs):
        try:
            log = LogModel.model_validate(raw_log)
            result = await ingest_log(log, organization_id, force_sync=True)
        except ValidationError as exc:
            rejected += 1
            errors.append({"index": index, "detail": exc.errors()})
            continue
        except Exception as exc:
            rejected += 1
            errors.append({"index": index, "detail": str(exc)})
            continue

        accepted += 1
        results.append(
            {
                "index": index,
                "log_id": result["log_id"],
                "event_id": result.get("event_id"),
                "record_id": result.get("record_id"),
                "alert_generated": result["alert_generated"],
                "alert_created": result.get("alert_created", result["alert_generated"]),
                "incident_created": result.get("incident_created", False),
                "duplicate": result.get("duplicate", False),
                "alert_id": result.get("alert_id"),
                "incident_id": result.get("incident_id"),
                "matched_rule": result.get("matched_rule"),
                "task_id": result.get("task_id"),
            }
        )

    now = datetime.now(timezone.utc)
    if not collector.get("env_configured"):
        await collectors_collection.update_one(
            {"_id": collector["_id"]},
            {"$set": {"last_seen_at": now, "updated_at": now}},
        )

    return {
        "message": "Collector batch processed",
        "collector_id": str(collector["_id"]),
        "organization_id": organization_id,
        "accepted": accepted,
        "rejected": rejected,
        "results": results,
        "errors": errors,
    }
