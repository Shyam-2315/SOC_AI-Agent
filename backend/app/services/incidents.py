from datetime import datetime, timezone

from fastapi import HTTPException

from app.common.mongo import paginated_response, parse_object_id, serialize_document
from app.common.pagination import Pagination
from app.db.client import incidents_collection
from app.schemas.incident import IncidentCreate, IncidentUpdate
from app.services.audit import write_audit_event


async def create_incident(
    incident: IncidentCreate,
    user: dict,
) -> dict:
    incident_data = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "assigned_to": incident.assigned_to,
        "status": "open",
        "created_by": user["email"],
        "organization_id": user["organization_id"],
        "timestamp": datetime.now(timezone.utc),
    }
    result = await incidents_collection.insert_one(incident_data)
    incident_data["_id"] = result.inserted_id
    await write_audit_event(
        event_type="incident.created",
        actor=user,
        target_type="incident",
        target_id=str(result.inserted_id),
        metadata={"severity": incident.severity},
    )
    return {
        "message": "Incident created",
        "incident": serialize_document(incident_data),
    }


async def list_incidents(
    organization_id: str,
    pagination: Pagination,
) -> dict:
    query = {"organization_id": organization_id}
    items = []
    cursor = (
        incidents_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )
    async for incident in cursor:
        items.append(serialize_document(incident))

    total = await incidents_collection.count_documents(query)
    return paginated_response(items, total, pagination)


async def update_incident_status(
    incident_id: str,
    update: IncidentUpdate,
    user: dict,
) -> dict:
    object_id = parse_object_id(incident_id, "incident")
    result = await incidents_collection.update_one(
        {
            "_id": object_id,
            "organization_id": user["organization_id"],
        },
        {
            "$set": {
                "status": update.status,
                "updated_at": datetime.now(timezone.utc),
                "updated_by": user["email"],
            }
        },
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await write_audit_event(
        event_type="incident.status_updated",
        actor=user,
        target_type="incident",
        target_id=incident_id,
        metadata={"status": update.status},
    )
    return {"message": "Incident updated"}
