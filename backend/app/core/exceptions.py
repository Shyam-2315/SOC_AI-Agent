from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

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
    return JSONResponse(status_code=status_code, content=payload)


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    logger.warning(
        "http exception",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": exc.status_code,
        },
    )
    return _error_response(
        request=request,
        status_code=exc.status_code,
        code="http_error",
        message=str(exc.detail),
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
    logger.exception(
        "unhandled exception",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
    )
    return _error_response(
        request=request,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="internal_server_error",
        message="Internal server error",
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
