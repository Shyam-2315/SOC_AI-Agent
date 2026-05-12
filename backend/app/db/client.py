from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings


client = AsyncIOMotorClient(
    settings.mongo_url,
    appname=settings.app_name,
    serverSelectionTimeoutMS=settings.mongo_server_selection_timeout_ms,
    connectTimeoutMS=settings.mongo_connect_timeout_ms,
    socketTimeoutMS=settings.mongo_socket_timeout_ms,
    maxPoolSize=settings.mongo_max_pool_size,
    minPoolSize=settings.mongo_min_pool_size,
)
db = client[settings.database_name]

logs_collection = db["logs"]
alerts_collection = db["alerts"]
incidents_collection = db["incidents"]
users_collection = db["users"]
organizations_collection = db["organizations"]
response_actions_collection = db["response_actions"]
alert_processing_jobs_collection = db["alert_processing_jobs"]
audit_events_collection = db["audit_events"]
detection_rules_collection = db["detection_rules"]
detection_rule_packs_collection = db["detection_rule_packs"]
collectors_collection = db["collectors"]


async def ping_database() -> None:
    await client.admin.command("ping")


async def ping_database_with_retry(
    *,
    attempts: int = 5,
    delay_seconds: float = 1.0,
) -> None:
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            await ping_database()
            return
        except Exception as exc:
            last_error = exc
            if attempt == attempts:
                break
            import asyncio

            await asyncio.sleep(delay_seconds)
    raise last_error


async def close_database() -> None:
    client.close()
