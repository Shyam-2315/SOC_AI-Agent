from fastapi import APIRouter

from app.api.routes.alerts import router as alerts_router
from app.api.routes.auth import router as auth_router
from app.api.routes.copilot import router as copilot_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.ingestion import router as ingestion_router
from app.api.routes.logs import router as logs_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.soar import router as soar_router
from app.api.routes.threat_hunting import router as threat_hunting_router


api_router = APIRouter()
api_router.include_router(ingestion_router)
api_router.include_router(auth_router)
api_router.include_router(organizations_router)
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(soar_router)
api_router.include_router(threat_hunting_router)
api_router.include_router(copilot_router)
