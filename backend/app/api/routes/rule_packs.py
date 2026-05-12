from fastapi import APIRouter, Depends, Request, Response, status

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.schemas.rule_pack import DetectionPackCreate, DetectionPackUpdate
from app.services.rule_packs import (
    create_pack,
    delete_pack,
    export_pack,
    get_pack,
    import_pack,
    list_packs,
    list_starter_packs,
    update_pack,
)


router = APIRouter(
    prefix="/rule-packs",
    tags=["Detection Rule Packs"],
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_pack_endpoint(
    pack: DetectionPackCreate,
    user=Depends(require_permission("rules:write")),
):
    return await create_pack(pack, user)


@router.get("")
async def list_packs_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("rules:read")),
):
    return await list_packs(user["organization_id"], pagination)


@router.get("/starter")
async def list_starter_packs_endpoint(
    _user=Depends(require_permission("rules:read")),
):
    return await list_starter_packs()


@router.post("/import", status_code=status.HTTP_201_CREATED)
async def import_pack_endpoint(
    request: Request,
    user=Depends(require_permission("rules:write")),
):
    return await import_pack(
        await request.body(),
        request.headers.get("content-type", ""),
        user,
    )


@router.get("/{pack_id}")
async def get_pack_endpoint(
    pack_id: str,
    user=Depends(require_permission("rules:read")),
):
    return await get_pack(pack_id, user["organization_id"])


@router.patch("/{pack_id}")
async def update_pack_endpoint(
    pack_id: str,
    update: DetectionPackUpdate,
    user=Depends(require_permission("rules:write")),
):
    return await update_pack(pack_id, update, user)


@router.delete("/{pack_id}")
async def delete_pack_endpoint(
    pack_id: str,
    user=Depends(require_permission("rules:write")),
):
    return await delete_pack(pack_id, user)


@router.get("/{pack_id}/export")
async def export_pack_endpoint(
    pack_id: str,
    format: str = "json",
    user=Depends(require_permission("rules:read")),
):
    exported = await export_pack(pack_id, user["organization_id"], user, format.lower())
    if format.lower() in {"yaml", "yml"}:
        return Response(content=exported, media_type="application/x-yaml")
    return exported
