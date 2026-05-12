from fastapi import APIRouter, Depends, status

from app.api.dependencies import Pagination, pagination_params, require_permission
from app.schemas.rule import DetectionRuleCreate, DetectionRuleUpdate
from app.services.rules import create_rule, delete_rule, get_rule, list_rules, update_rule


router = APIRouter(
    prefix="/rules",
    tags=["Detection Rules"],
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_rule_endpoint(
    rule: DetectionRuleCreate,
    user=Depends(require_permission("rules:write")),
):
    return await create_rule(rule, user)


@router.get("")
async def list_rules_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("rules:read")),
):
    return await list_rules(user["organization_id"], pagination)


@router.get("/{rule_id}")
async def get_rule_endpoint(
    rule_id: str,
    user=Depends(require_permission("rules:read")),
):
    return await get_rule(rule_id, user["organization_id"])


@router.patch("/{rule_id}")
async def update_rule_endpoint(
    rule_id: str,
    update: DetectionRuleUpdate,
    user=Depends(require_permission("rules:write")),
):
    return await update_rule(rule_id, update, user)


@router.delete("/{rule_id}")
async def delete_rule_endpoint(
    rule_id: str,
    user=Depends(require_permission("rules:write")),
):
    return await delete_rule(rule_id, user)
