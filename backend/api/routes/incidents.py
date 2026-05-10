from fastapi import APIRouter, Depends, HTTPException

from schemas.incident_schema import (
    IncidentCreate,
    IncidentUpdate
)

from core.database import incidents_collection

from core.dependencies import (
    get_current_user
)

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"]
)


@router.post("/")
async def create_incident(
    incident: IncidentCreate,
    user=Depends(get_current_user)
):

    incident_dict = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "assigned_to": incident.assigned_to,
        "status": "Open",
        "created_by": user["email"]
    }

    result = await incidents_collection.insert_one(
        incident_dict
    )

    incident_dict["_id"] = str(result.inserted_id)

    return {
        "message": "Incident created",
        "incident": incident_dict
    }


@router.get("/")
async def get_incidents(
    user=Depends(get_current_user)
):

    incidents = []

    async for incident in incidents_collection.find():

        incident["_id"] = str(incident["_id"])

        incidents.append(incident)

    return incidents


@router.patch("/{incident_id}")
async def update_incident_status(
    incident_id: str,
    update: IncidentUpdate,
    user=Depends(get_current_user)
):

    result = await incidents_collection.update_one(
        {"_id": __import__("bson").ObjectId(incident_id)},
        {
            "$set": {
                "status": update.status
            }
        }
    )

    if result.modified_count == 0:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return {
        "message": "Incident updated"
    }