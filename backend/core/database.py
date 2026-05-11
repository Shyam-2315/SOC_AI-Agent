from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING

from core.config import settings


client = AsyncIOMotorClient(settings.mongo_url)
db = client[settings.database_name]

logs_collection = db["logs"]
alerts_collection = db["alerts"]
incidents_collection = db["incidents"]
users_collection = db["users"]
organizations_collection = db["organizations"]
response_actions_collection = db["response_actions"]


async def ping_database() -> None:
    await client.admin.command("ping")


async def close_database() -> None:
    client.close()


async def create_indexes() -> None:
    await users_collection.create_index(
        [("email", ASCENDING)],
        unique=True,
    )
    await users_collection.create_index(
        [("organization_id", ASCENDING), ("role", ASCENDING)],
    )
    await organizations_collection.create_index(
        [("name", ASCENDING)],
        unique=True,
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)],
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("event_type", ASCENDING)],
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("severity", ASCENDING)],
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)],
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)],
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("severity", ASCENDING)],
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("event_type", ASCENDING)],
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)],
    )
    await incidents_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)],
    )
    await incidents_collection.create_index(
        [("organization_id", ASCENDING), ("status", ASCENDING)],
    )
    await response_actions_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)],
    )
    await response_actions_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)],
    )
