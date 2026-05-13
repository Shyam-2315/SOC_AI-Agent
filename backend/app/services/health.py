import asyncio
from typing import Any

from app.core.config import settings
from app.db.client import ping_database
from app.realtime.manager import manager
from app.realtime.pubsub import get_redis_client


async def check_mongo() -> dict[str, Any]:
    try:
        await ping_database()
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def check_redis() -> dict[str, Any]:
    if not settings.redis_url:
        return {"status": "disabled"}
    try:
        redis_client = await get_redis_client()
        if redis_client is None:
            return {"status": "disabled"}
        await redis_client.ping()
        return {"status": "ok"}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


async def check_celery() -> dict[str, Any]:
    if not settings.celery_enabled:
        return {"status": "disabled"}

    try:
        from app.workers.celery_app import celery_app

        responses = await asyncio.to_thread(
            celery_app.control.ping,
            timeout=1.0,
            destination=None,
        )
        return {
            "status": "ok" if responses else "degraded",
            "workers": len(responses or []),
        }
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}


def check_websockets() -> dict[str, Any]:
    return {"status": "ok", **manager.get_connection_stats()}


def check_syslog_receiver() -> dict[str, Any]:
    return {
        "status": "enabled" if settings.syslog_enabled else "disabled",
        "mode": "external-worker",
        "host": settings.syslog_host,
        "port": settings.syslog_port,
        "transport": "udp",
        "collector_token_configured": bool(settings.syslog_collector_token),
    }


async def readiness() -> dict[str, Any]:
    mongo, redis, celery = await asyncio.gather(
        check_mongo(),
        check_redis(),
        check_celery(),
    )
    checks = {
        "mongo": mongo,
        "redis": redis,
        "celery": celery,
        "websockets": check_websockets(),
        "syslog_receiver": check_syslog_receiver(),
    }
    required = [mongo]
    if settings.redis_url:
        required.append(redis)
    if settings.celery_enabled:
        required.append(celery)
    status = "healthy" if all(item["status"] in {"ok", "disabled"} for item in required) else "unhealthy"
    return {
        "status": status,
        "environment": settings.environment.value,
        "version": settings.app_version,
        "checks": checks,
    }
