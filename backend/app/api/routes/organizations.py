from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import auth_rate_limit, get_optional_current_user, require_permission
from app.core.config import settings
from app.core.rbac import has_permission
from app.schemas.organization import OrganizationCreate
from app.services.organizations import create_organization, get_current_organization


router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"],
)


@router.post("/")
async def create_organization_endpoint(
    organization: OrganizationCreate,
    user=Depends(get_optional_current_user),
    _: None = Depends(auth_rate_limit),
):
    if user is None:
        if not settings.public_registration_enabled:
            raise HTTPException(status_code=404, detail="Organization registration is disabled")
    elif not has_permission(user["role"], "organizations:write"):
        raise HTTPException(
            status_code=403,
            detail="Missing permission: organizations:write",
        )
    return await create_organization(organization, user)


@router.get("/me")
async def get_current_organization_endpoint(
    user=Depends(require_permission("organizations:read")),
):
    return await get_current_organization(user)
