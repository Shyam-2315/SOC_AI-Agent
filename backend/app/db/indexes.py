from pymongo import ASCENDING, DESCENDING

from app.db.client import (
    alerts_collection,
    alert_processing_jobs_collection,
    audit_events_collection,
    incidents_collection,
    logs_collection,
    organizations_collection,
    response_actions_collection,
    users_collection,
)


async def create_indexes() -> None:
    await users_collection.create_index([("email", ASCENDING)], unique=True)
    await users_collection.create_index(
        [("organization_id", ASCENDING), ("role", ASCENDING)]
    )
    await organizations_collection.create_index([("name", ASCENDING)], unique=True)
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)]
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("event_type", ASCENDING)]
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("severity", ASCENDING)]
    )
    await logs_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)]
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)]
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("severity", ASCENDING)]
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("event_type", ASCENDING)]
    )
    await alerts_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)]
    )
    await incidents_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)]
    )
    await incidents_collection.create_index(
        [("organization_id", ASCENDING), ("status", ASCENDING)]
    )
    await response_actions_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)]
    )
    await response_actions_collection.create_index(
        [("organization_id", ASCENDING), ("ip_address", ASCENDING)]
    )
    await alert_processing_jobs_collection.create_index(
        [("task_id", ASCENDING)],
        unique=True,
    )
    await alert_processing_jobs_collection.create_index(
        [("organization_id", ASCENDING), ("created_at", DESCENDING)]
    )
    await audit_events_collection.create_index(
        [("organization_id", ASCENDING), ("timestamp", DESCENDING)]
    )
    await audit_events_collection.create_index(
        [("event_type", ASCENDING), ("timestamp", DESCENDING)]
    )
