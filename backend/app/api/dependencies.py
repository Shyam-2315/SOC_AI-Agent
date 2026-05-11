import secrets

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, WebSocket, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.common.pagination import Pagination, pagination_params
from app.core.config import settings
from app.core.rate_limit import check_rate_limit, client_ip
from app.core.rbac import has_permission
from app.core.security import UserRole, verify_token
from app.db.client import users_collection


security = HTTPBearer(auto_error=False)
collector_token_header = APIKeyHeader(
    name="X-Collector-Token",
    auto_error=False,
)


async def _load_current_user_from_claims(claims: dict) -> dict:
    user_id = claims.get("user_id")
    if not user_id or not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=401,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.get("disabled"):
        raise HTTPException(status_code=403, detail="User is disabled")

    return {
        "user_id": str(user["_id"]),
        "username": user.get("username"),
        "email": user["email"],
        "role": user["role"],
        "organization_id": user["organization_id"],
        "disabled": user.get("disabled", False),
    }


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    claims = verify_token(credentials.credentials)
    return await _load_current_user_from_claims(claims)


def require_admin(user=Depends(get_current_user)):
    if user["role"] != UserRole.admin.value:
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return user


def require_permission(permission: str):
    async def dependency(user=Depends(get_current_user)):
        if not has_permission(user["role"], permission):
            raise HTTPException(
                status_code=403,
                detail=f"Missing permission: {permission}",
            )
        return user

    return dependency


def auth_rate_limit(request: Request) -> None:
    check_rate_limit(
        key=f"auth:{client_ip(request)}",
        limit=settings.auth_rate_limit_per_minute,
    )


def ingestion_rate_limit(request: Request) -> None:
    token_hint = request.headers.get("x-collector-token", "")
    key = token_hint or client_ip(request)
    check_rate_limit(
        key=f"ingest:{key}",
        limit=settings.ingestion_rate_limit_per_minute,
    )


def get_collector_organization_id(
    token: str = Depends(collector_token_header),
    _: None = Depends(ingestion_rate_limit),
) -> str:
    if not settings.collector_api_keys:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Collector ingestion is not configured",
        )

    organization_id = None
    for configured_token, configured_organization_id in settings.collector_api_keys.items():
        if token and secrets.compare_digest(token, configured_token):
            organization_id = configured_organization_id
            break

    if organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid collector token",
        )

    return organization_id


async def get_websocket_user(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin and origin not in settings.cors_origins:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None

    token = websocket.query_params.get("token")
    if not token:
        authorization = websocket.headers.get("authorization", "")
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = value

    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None

    try:
        claims = verify_token(token)
        return await _load_current_user_from_claims(claims)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None


__all__ = [
    "Pagination",
    "collector_token_header",
    "get_collector_organization_id",
    "get_current_user",
    "get_websocket_user",
    "pagination_params",
    "require_admin",
    "require_permission",
    "auth_rate_limit",
    "ingestion_rate_limit",
    "security",
]
