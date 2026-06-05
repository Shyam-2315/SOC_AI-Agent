from fastapi import APIRouter

from app.api.routes.alerts import router as alerts_router
from app.api.routes.attack_chains import router as attack_chains_router
from app.api.routes.ai_copilot import router as ai_copilot_router
from app.api.routes.auth import router as auth_router
from app.api.routes.collectors import router as collectors_router
from app.api.routes.copilot import router as copilot_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.ingestion import router as ingestion_router
from app.api.routes.logs import router as logs_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.reports import router as reports_router
from app.api.routes.rule_packs import router as rule_packs_router
from app.api.routes.rules import router as rules_router
from app.api.routes.security import router as security_router
from app.api.routes.soar import router as soar_router
from app.api.routes.threat_hunting import router as threat_hunting_router
from app.api.routes.threat_intel import router as threat_intel_router


api_router = APIRouter()
api_router.include_router(ingestion_router)
api_router.include_router(auth_router)
api_router.include_router(organizations_router)
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(attack_chains_router)
api_router.include_router(ai_copilot_router)
api_router.include_router(collectors_router)
api_router.include_router(rule_packs_router)
api_router.include_router(rules_router)
api_router.include_router(security_router)
api_router.include_router(incidents_router)
api_router.include_router(soar_router)
api_router.include_router(threat_hunting_router)
api_router.include_router(threat_intel_router)
api_router.include_router(copilot_router)
api_router.include_router(reports_router)
