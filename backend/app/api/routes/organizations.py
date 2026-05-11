from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.schemas.organization import OrganizationCreate
from app.services.organizations import create_organization, get_current_organization


router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
)


@router.post("/")
async def create_organization_endpoint(
    organization: OrganizationCreate,
    user=Depends(require_permission("organizations:write")),
):
    return await create_organization(organization, user)


@router.get("/me")
async def get_current_organization_endpoint(
    user=Depends(require_permission("organizations:read")),
):
    return await get_current_organization(user)
