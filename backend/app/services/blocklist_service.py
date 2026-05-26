from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from app.core.logging import get_logger
from app.db.client import security_blocks_collection
from app.realtime.pubsub import get_redis_client


BLOCK_PREFIX = "blocklist:ip:"
logger = get_logger(__name__)


def _normalize_ip(value: str) -> str:
    return str(ip_address(value.strip()))


def _key(ip: str) -> str:
    return f"{BLOCK_PREFIX}{ip}"


async def block_ip(
    ip: str,
    reason: str,
    duration_minutes: int,
    *,
    organization_id: str | None = None,
    blocked_by: str = "system",
) -> dict:
    normalized_ip = _normalize_ip(ip)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=max(duration_minutes, 1))
    document = {
        "ip_address": normalized_ip,
        "reason": reason,
        "duration_minutes": max(duration_minutes, 1),
        "organization_id": organization_id,
        "blocked_by": blocked_by,
        "active": True,
        "blocked_at": now,
        "expires_at": expires_at,
        "updated_at": now,
    }
    await security_blocks_collection.update_one(
        {"ip_address": normalized_ip},
        {"$set": document},
        upsert=True,
    )

    redis_client = await get_redis_client()
    if redis_client is not None:
        ttl_seconds = max(int((expires_at - now).total_seconds()), 1)
        try:
            await redis_client.set(_key(normalized_ip), reason, ex=ttl_seconds)
        except Exception:
            logger.exception("failed to write blocklist entry to redis", extra={"source_ip": normalized_ip})

    return document


async def unblock_ip(ip: str) -> dict:
    normalized_ip = _normalize_ip(ip)
    now = datetime.now(timezone.utc)
    await security_blocks_collection.update_one(
        {"ip_address": normalized_ip},
        {"$set": {"active": False, "updated_at": now, "unblocked_at": now}},
        upsert=True,
    )

    redis_client = await get_redis_client()
    if redis_client is not None:
        try:
            await redis_client.delete(_key(normalized_ip))
        except Exception:
            logger.exception("failed to delete blocklist entry from redis", extra={"source_ip": normalized_ip})

    return {"ip_address": normalized_ip, "active": False}


async def is_blocked(ip: str) -> bool:
    try:
        normalized_ip = _normalize_ip(ip)
    except ValueError:
        return False

    redis_client = await get_redis_client()
    if redis_client is not None:
        try:
            blocked = await redis_client.exists(_key(normalized_ip))
            if blocked:
                return True
        except Exception:
            logger.exception("failed to read blocklist entry from redis", extra={"source_ip": normalized_ip})

    now = datetime.now(timezone.utc)
    document = await security_blocks_collection.find_one(
        {"ip_address": normalized_ip, "active": True}
    )
    if not document:
        return False
    expires_at = document.get("expires_at")
    if isinstance(expires_at, datetime) and expires_at <= now:
        await security_blocks_collection.update_one(
            {"ip_address": normalized_ip},
            {"$set": {"active": False, "updated_at": now, "expired_at": now}},
        )
        return False
    return True


async def list_blocked_ips(organization_id: str | None = None) -> list[dict]:
    now = datetime.now(timezone.utc)
    query: dict = {"active": True}
    if organization_id:
        query["$or"] = [{"organization_id": organization_id}, {"organization_id": None}]

    items = []
    cursor = security_blocks_collection.find(query).sort("blocked_at", -1)
    async for document in cursor:
        expires_at = document.get("expires_at")
        if isinstance(expires_at, datetime) and expires_at <= now:
            await security_blocks_collection.update_one(
                {"_id": document["_id"]},
                {"$set": {"active": False, "updated_at": now, "expired_at": now}},
            )
            continue
        items.append(
            {
                "ip_address": document["ip_address"],
                "reason": document.get("reason"),
                "organization_id": document.get("organization_id"),
                "blocked_by": document.get("blocked_by"),
                "blocked_at": document.get("blocked_at"),
                "expires_at": document.get("expires_at"),
                "duration_minutes": document.get("duration_minutes"),
            }
        )
    return items
