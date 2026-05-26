from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.logging import get_logger


logger = get_logger(__name__)


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _error_response(
    *,
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details=None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    payload = {
        "error": {
            "code": code,
            "message": message,
        },
        "request_id": _request_id(request),
    }
    if details is not None:
        payload["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=payload, headers=headers)


def _http_error_code(status_code: int) -> str:
    return {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        413: "request_too_large",
        422: "validation_error",
        429: "rate_limit_exceeded",
        503: "service_unavailable",
    }.get(status_code, "http_error")


def _http_error_parts(exc: HTTPException) -> tuple[str, str, object | None]:
    if isinstance(exc.detail, dict):
        error = exc.detail.get("error")
        if isinstance(error, dict):
            return (
                str(error.get("code") or _http_error_code(exc.status_code)),
                str(error.get("message") or "Request failed"),
                error.get("details"),
            )
        return (
            str(exc.detail.get("code") or _http_error_code(exc.status_code)),
            str(exc.detail.get("message") or "Request failed"),
            exc.detail.get("details"),
        )
    if isinstance(exc.detail, list):
        return _http_error_code(exc.status_code), "Request failed", exc.detail
    return _http_error_code(exc.status_code), str(exc.detail), None


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    code, message, details = _http_error_parts(exc)
    logger.warning(
        "http exception",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": exc.status_code,
            "client_ip": getattr(request.state, "client_ip", None),
            "organization_id": getattr(request.state, "organization_id", None),
        },
    )
    return _error_response(
        request=request,
        status_code=exc.status_code,
        code=code,
        message=message,
        details=details,
        headers=exc.headers,
    )


def _validation_details(exc: RequestValidationError) -> list[dict]:
    details = []
    for error in exc.errors():
        details.append(
            {
                "loc": error.get("loc"),
                "msg": error.get("msg"),
                "type": error.get("type"),
            }
        )
    return details


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    logger.warning(
        "validation error",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
            "client_ip": getattr(request.state, "client_ip", None),
            "organization_id": getattr(request.state, "organization_id", None),
        },
    )
    return _error_response(
        request=request,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="validation_error",
        message="Request validation failed",
        details=_validation_details(exc),
    )


async def unhandled_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    details = None
    if settings.debug:
        details = {"exception": type(exc).__name__}
    logger.exception(
        "unhandled exception",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
            "client_ip": getattr(request.state, "client_ip", None),
            "organization_id": getattr(request.state, "organization_id", None),
        },
    )
    return _error_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="internal_server_error",
        message="Internal server error",
        details=details,
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
