from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from core.database import incidents_collection
from core.dependencies import Pagination, get_current_user, pagination_params
from schemas.incident_schema import IncidentCreate, IncidentUpdate


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


@router.post("/")
async def create_incident(
    incident: IncidentCreate,
    user=Depends(get_current_user),
):
    incident_dict = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "assigned_to": incident.assigned_to,
        "status": "open",
        "created_by": user["email"],
        "organization_id": user["organization_id"],
        "timestamp": datetime.now(timezone.utc),
    }

    result = await incidents_collection.insert_one(incident_dict)
    incident_dict["_id"] = str(result.inserted_id)

    return {
        "message": "Incident created",
        "incident": incident_dict,
    }


@router.get("/")
async def get_incidents(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(get_current_user),
):
    query = {
        "organization_id": user["organization_id"],
    }

    incidents = []
    cursor = (
        incidents_collection.find(query)
        .sort("timestamp", -1)
        .skip(pagination.offset)
        .limit(pagination.limit)
    )

    async for incident in cursor:
        incident["_id"] = str(incident["_id"])
        incidents.append(incident)

    total = await incidents_collection.count_documents(query)

    return {
        "items": incidents,
        "total": total,
        "limit": pagination.limit,
        "offset": pagination.offset,
    }


@router.patch("/{incident_id}")
async def update_incident_status(
    incident_id: str,
    update: IncidentUpdate,
    user=Depends(get_current_user),
):
    try:
        object_id = ObjectId(incident_id)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid incident id",
        )

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
            },
        },
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "message": "Incident updated",
    }
