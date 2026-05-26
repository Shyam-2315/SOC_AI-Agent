from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.schemas.security import SecurityBlockRequest
from app.services.blocklist_service import block_ip, list_blocked_ips, unblock_ip
from app.services.dos_ddos_detection_service import get_security_summary


router = APIRouter(tags=["Security"])
security_router = APIRouter(prefix="/security")
legacy_security_router = APIRouter(prefix="/api/v1/security")


def _register_security_routes(target: APIRouter) -> None:
    @target.get("/traffic/summary")
    async def traffic_summary(
        user=Depends(require_permission("security:read")),
    ):
        return await get_security_summary(user["organization_id"])

    @target.get("/blocked-ips")
    async def blocked_ips(
        user=Depends(require_permission("security:read")),
    ):
        return {
            "items": await list_blocked_ips(user["organization_id"]),
        }

    @target.post("/block-ip")
    async def block_ip_endpoint(
        payload: SecurityBlockRequest,
        user=Depends(require_permission("security:write")),
    ):
        result = await block_ip(
            payload.ip,
            payload.reason or "Manual analyst block",
            payload.duration_minutes,
            organization_id=user["organization_id"],
            blocked_by=user["email"],
        )
        return {"message": "IP blocked", "item": result}

    @target.post("/unblock-ip")
    async def unblock_ip_endpoint(
        payload: SecurityBlockRequest,
        user=Depends(require_permission("security:write")),
    ):
        _ = user
        result = await unblock_ip(payload.ip)
        return {"message": "IP unblocked", "item": result}


_register_security_routes(security_router)
_register_security_routes(legacy_security_router)
router.include_router(security_router)
router.include_router(legacy_security_router)

