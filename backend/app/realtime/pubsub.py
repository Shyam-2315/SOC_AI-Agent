import asyncio
import json
from typing import Optional

from redis.asyncio import Redis
from redis.asyncio import from_url as redis_from_url

from app.core.config import settings
from app.core.logging import get_logger
from app.realtime.manager import manager


logger = get_logger(__name__)
_redis_client: Optional[Redis] = None


async def get_redis_client() -> Optional[Redis]:
    global _redis_client

    if not settings.redis_url:
        return None

    if _redis_client is None:
        _redis_client = redis_from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            retry_on_timeout=True,
            health_check_interval=30,
        )

    return _redis_client


async def close_redis_client() -> None:
    global _redis_client

    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


async def publish_realtime_event(
    event: dict,
) -> None:
    redis_client = await get_redis_client()
    if redis_client is None:
        await manager.publish(event)
        return

    payload = json.dumps(event, default=str)

    try:
        await redis_client.publish(settings.realtime_events_channel, payload)
    except Exception:
        logger.exception(
            "failed to publish realtime event",
            extra={
                "organization_id": event.get("organization_id"),
                "event_type": event.get("event_type"),
            },
        )


async def run_realtime_event_listener(stop_event: asyncio.Event) -> None:
    redis_client = await get_redis_client()
    if redis_client is None:
        return

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(settings.realtime_events_channel)
    logger.info(
        "started realtime event listener",
        extra={"channel": settings.realtime_events_channel},
    )

    try:
        while not stop_event.is_set():
            message = await pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=1.0,
            )
            if message is None:
                continue

            try:
                event = json.loads(message["data"])
                await manager.publish(event)
            except Exception:
                logger.exception("failed to dispatch redis realtime event")
    except asyncio.CancelledError:
        raise
    finally:
        await pubsub.unsubscribe(settings.realtime_events_channel)
        await pubsub.aclose()
        logger.info("stopped realtime event listener")
