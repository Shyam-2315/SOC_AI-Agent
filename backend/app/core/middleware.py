from time import perf_counter
from uuid import uuid4

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import Settings
from app.core.logging import (
    client_ip_context,
    get_logger,
    organization_id_context,
    request_id_context,
)
from app.core.security import verify_token
from app.services.blocklist_service import is_blocked
from app.services.dos_ddos_detection_service import process_traffic_event


logger = get_logger(__name__)


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    if request.client:
        return request.client.host
    return "unknown"


def _organization_id_from_request(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = verify_token(token)
            organization_id = claims.get("organization_id")
            if isinstance(organization_id, str) and organization_id:
                return organization_id
        except Exception:
            return None
    return None


class TrafficProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        source_ip = getattr(request.state, "client_ip", None) or _client_ip(request)
        path = request.url.path
        is_health = path.startswith("/health")

        try:
            if not is_health and await is_blocked(source_ip):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "code": "traffic_blocked",
                        "message": "Request blocked due to suspicious traffic behavior",
                    },
                )

            response = await call_next(request)
        except HTTPException:
            raise
        finally:
            response_status = getattr(locals().get("response"), "status_code", 500)
            try:
                await process_traffic_event(
                    source_ip=source_ip,
                    path=path,
                    method=request.method,
                    status_code=response_status,
                    user_agent=request.headers.get("user-agent"),
                    organization_id=getattr(request.state, "organization_id", None)
                    or _organization_id_from_request(request),
                )
            except Exception:
                logger.exception(
                    "failed to process traffic event",
                    extra={
                        "path": path,
                        "client_ip": source_ip,
                        "status_code": response_status,
                        "organization_id": getattr(request.state, "organization_id", None),
                    },
                )
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                length = 0
            if length > self.settings.request_max_body_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail={
                        "code": "request_too_large",
                        "message": "Request body exceeds the configured size limit",
                        "details": {
                            "max_body_bytes": self.settings.request_max_body_bytes,
                        },
                    },
                )
        return await call_next(request)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        request.state.request_id = request_id
        request.state.started_at = perf_counter()
        request.state.client_ip = _client_ip(request)
        request.state.organization_id = _organization_id_from_request(request)
        request_id_token = request_id_context.set(request_id)
        client_ip_token = client_ip_context.set(request.state.client_ip)
        organization_token = organization_id_context.set(request.state.organization_id or "-")

        try:
            response = await call_next(request)
            duration_ms = round((perf_counter() - request.state.started_at) * 1000, 2)
            response.headers["X-Request-ID"] = request_id
            logger.info(
                "request completed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "client_ip": request.state.client_ip,
                    "organization_id": request.state.organization_id,
                },
            )
            return response
        finally:
            organization_id_context.reset(organization_token)
            client_ip_context.reset(client_ip_token)
            request_id_context.reset(request_id_token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss: http: https:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault("Cache-Control", "no-store")
        if self.settings.https_redirect:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
