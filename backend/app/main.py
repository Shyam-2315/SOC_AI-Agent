from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.api.websockets import websocket_alerts
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.startup import validate_startup_dependencies
from app.db.client import close_database
from app.db.indexes import create_indexes
from app.realtime.pubsub import close_redis_client, run_realtime_event_listener
from app.services.health import readiness


configure_logging(settings)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(
        "starting application",
        extra={"environment": settings.environment.value},
    )
    await validate_startup_dependencies()
    await create_indexes()
    redis_listener_stop = asyncio.Event()
    redis_listener_task = None
    if settings.redis_url:
        redis_listener_task = asyncio.create_task(
            run_realtime_event_listener(redis_listener_stop)
        )
    yield
    if redis_listener_task is not None:
        redis_listener_stop.set()
        redis_listener_task.cancel()
        try:
            await redis_listener_task
        except asyncio.CancelledError:
            pass
    await close_redis_client()
    await close_database()
    logger.info("application shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts or ["*"],
    )
    if settings.https_redirect:
        app.add_middleware(HTTPSRedirectMiddleware)
    local_dev_origin_regex = None
    if not settings.is_production:
        local_dev_origin_regex = r"https?://(localhost|127\.0\.0\.1):\d+"

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_origin_regex=local_dev_origin_regex,
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router)
    app.add_api_websocket_route("/ws/alerts", websocket_alerts)

    @app.get("/")
    def root():
        return {
            "message": f"{settings.app_name} Running",
            "environment": settings.environment.value,
            "version": settings.app_version,
        }

    @app.get("/health")
    async def health():
        result = await readiness()
        if result["status"] != "healthy":
            raise HTTPException(status_code=503, detail=result)
        return result

    @app.get("/health/live")
    async def health_live():
        return {
            "status": "alive",
            "environment": settings.environment.value,
            "version": settings.app_version,
        }

    @app.get("/health/ready")
    async def health_ready():
        result = await readiness()
        if result["status"] != "healthy":
            raise HTTPException(status_code=503, detail=result)
        return result

    return app


app = create_app()
