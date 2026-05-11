from datetime import datetime, timezone

from fastapi import HTTPException

from app.common.mongo import parse_object_id, serialize_document
from app.db.client import organizations_collection
from app.schemas.organization import OrganizationCreate
from app.services.audit import write_audit_event


async def create_organization(
    organization: OrganizationCreate,
    user: dict,
) -> dict:
    organization_data = {
        "name": organization.name,
        "created_at": datetime.now(timezone.utc),
        "created_by": user["email"],
    }
    result = await organizations_collection.insert_one(organization_data)
    await write_audit_event(
        event_type="organization.created",
        actor=user,
        organization_id=str(result.inserted_id),
        target_type="organization",
        target_id=str(result.inserted_id),
        metadata={"name": organization.name},
    )
    return {
        "message": "Organization created",
        "organization_id": str(result.inserted_id),
    }


async def get_current_organization(user: dict) -> dict:
    object_id = parse_object_id(user["organization_id"], "organization")
    organization = await organizations_collection.find_one({"_id": object_id})
    if not organization:
        raise HTTPException(
            status_code=404,
            detail="Organization not found",
        )
    return serialize_document(organization)
