import asyncio

from app.core.config import settings
from app.core.logging import get_logger
from app.db.client import ping_database_with_retry
from app.realtime.pubsub import get_redis_client


logger = get_logger(__name__)


async def validate_startup_dependencies() -> None:
    logger.info("validating startup dependencies")
    await ping_database_with_retry(attempts=5, delay_seconds=1.0)

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
