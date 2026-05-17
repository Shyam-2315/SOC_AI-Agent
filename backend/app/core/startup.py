import asyncio

from bson import ObjectId

from app.core.config import settings
from app.core.logging import get_logger
from app.db.client import organizations_collection
from app.db.client import ping_database_with_retry
from app.realtime.pubsub import get_redis_client


logger = get_logger(__name__)


async def ensure_development_collector_organizations() -> None:
    if settings.is_production:
        return

    for organization_id in set(settings.collector_api_keys.values()):
        if not ObjectId.is_valid(organization_id):
            continue
        object_id = ObjectId(organization_id)
        await organizations_collection.update_one(
            {"_id": object_id},
            {
                "$setOnInsert": {
                    "_id": object_id,
                    "name": f"Collector Test Org {organization_id[-6:]}",
                    "created_by": "startup",
                }
            },
            upsert=True,
        )


async def validate_startup_dependencies() -> None:
    logger.info("validating startup dependencies")
    await ping_database_with_retry(attempts=5, delay_seconds=1.0)
    await ensure_development_collector_organizations()

    if settings.redis_url:
        redis_client = await get_redis_client()
        if redis_client is not None:
            last_error = None
            for attempt in range(1, 6):
                try:
                    await redis_client.ping()
                    break
                except Exception as exc:
                    last_error = exc
                    if attempt == 5:
                        raise
                    await asyncio.sleep(1.0)

    if settings.celery_enabled and not settings.celery_broker_url:
        raise RuntimeError("Celery is enabled but CELERY_BROKER_URL is missing")
