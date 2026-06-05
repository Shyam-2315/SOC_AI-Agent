from fastapi import APIRouter, Depends, Query

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.repositories.attack_chain_repository import (
    get_attack_chain,
    list_attack_chains,
    update_attack_chain_status,
)
from app.schemas.attack_chain import (
    AttackChainRead,
    AttackChainStatusUpdate,
    AttackGraphResponse,
)
from app.services.attack_chain_service import (
    generate_attack_chains,
    get_attack_chain_graph,
    get_attack_chain_story,
)


router = APIRouter(
    prefix="/attack-chains",
    tags=["Attack Chains"],
)


@router.post("/generate")
async def generate_attack_chains_endpoint(
    lookback_hours: int = Query(default=24, ge=1, le=336),
    user=Depends(require_permission("attack_chains:write")),
):
    return await generate_attack_chains(user["organization_id"], lookback_hours)


@router.get("/")
async def list_attack_chains_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("attack_chains:read")),
):
    return await list_attack_chains(user["organization_id"], pagination)


@router.get("/{chain_id}", response_model=AttackChainRead)
async def get_attack_chain_endpoint(
    chain_id: str,
    user=Depends(require_permission("attack_chains:read")),
):
    return await get_attack_chain(chain_id, user["organization_id"])


@router.patch("/{chain_id}/status", response_model=AttackChainRead)
async def update_attack_chain_status_endpoint(
    chain_id: str,
    update: AttackChainStatusUpdate,
    user=Depends(require_permission("attack_chains:write")),
):
    return await update_attack_chain_status(chain_id, user["organization_id"], update.status)


@router.get("/{chain_id}/story")
async def get_attack_chain_story_endpoint(
    chain_id: str,
    user=Depends(require_permission("attack_chains:read")),
):
    return await get_attack_chain_story(chain_id, user["organization_id"])


@router.get("/{chain_id}/graph", response_model=AttackGraphResponse)
async def get_attack_chain_graph_endpoint(
    chain_id: str,
    user=Depends(require_permission("attack_chains:read")),
):
    return await get_attack_chain_graph(chain_id, user["organization_id"])
