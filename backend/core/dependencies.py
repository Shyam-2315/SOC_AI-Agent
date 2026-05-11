from fastapi import Depends, HTTPException, Query, WebSocket, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from core.config import settings
from core.security import UserRole, verify_token


security = HTTPBearer()
collector_token_header = APIKeyHeader(
    name="X-Collector-Token",
    auto_error=False,
)


class Pagination(BaseModel):
    limit: int
    offset: int


def pagination_params(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Pagination:
    return Pagination(
        limit=limit,
        offset=offset,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials
    return verify_token(token)


def require_admin(
    user=Depends(get_current_user),
):
    if user["role"] != UserRole.admin.value:
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )

    return user


def get_collector_organization_id(
    token: str = Depends(collector_token_header),
) -> str:
    if not settings.collector_api_keys:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Collector ingestion is not configured",
        )

    organization_id = settings.collector_api_keys.get(token or "")
    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid collector token",
        )

    return organization_id


async def get_websocket_user(websocket: WebSocket):
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
        return verify_token(token)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
