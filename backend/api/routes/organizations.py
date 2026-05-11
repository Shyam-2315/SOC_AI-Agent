from datetime import datetime, timezone

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from core.database import organizations_collection
from core.dependencies import require_admin
from models.organization_model import OrganizationCreate


router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
)


@router.post("/")
async def create_organization(
    organization: OrganizationCreate,
    user=Depends(require_admin),
):
    organization_data = {
        "name": organization.name,
        "created_at": datetime.now(timezone.utc),
        "created_by": user["email"],
    }

    result = await organizations_collection.insert_one(organization_data)

    return {
        "message": "Organization created",
        "organization_id": str(result.inserted_id),
    }


@router.get("/me")
async def get_current_organization(
    user=Depends(require_admin),
):
    try:
        object_id = ObjectId(user["organization_id"])
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid organization id",
        )

    organization = await organizations_collection.find_one({
        "_id": object_id,
    })
    if not organization:
        raise HTTPException(
            status_code=404,
            detail="Organization not found",
        )

    organization["_id"] = str(organization["_id"])
    return organization
