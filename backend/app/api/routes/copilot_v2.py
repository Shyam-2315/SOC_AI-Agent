from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.schemas.copilot_v2 import (
    CopilotAnswerResponse,
    CopilotContextSummary,
    CopilotQuestionRequest,
    CopilotReportResponse,
)
from app.services.copilot_v2_service import (
    ask_copilot_v2,
    generate_incident_report,
    recommend_attack_chain_actions,
    summarize_attack_chain_context,
    summarize_incident_context,
)


router = APIRouter(
    prefix="/copilot/v2",
    tags=["SOC Analyst Copilot v2"],
)


@router.post("/ask", response_model=CopilotAnswerResponse)
async def ask_copilot_v2_endpoint(
    request: CopilotQuestionRequest,
    user=Depends(require_permission("copilot:query")),
):
    return await ask_copilot_v2(request, user["organization_id"])


@router.get("/incidents/{incident_id}/summary", response_model=CopilotContextSummary)
async def incident_summary_endpoint(
    incident_id: str,
    user=Depends(require_permission("copilot:query")),
):
    return await summarize_incident_context(incident_id, user["organization_id"])


@router.get("/attack-chains/{chain_id}/summary", response_model=CopilotContextSummary)
async def attack_chain_summary_endpoint(
    chain_id: str,
    user=Depends(require_permission("copilot:query")),
):
    return await summarize_attack_chain_context(chain_id, user["organization_id"])


@router.get("/incidents/{incident_id}/executive-report", response_model=CopilotReportResponse)
async def incident_executive_report_endpoint(
    incident_id: str,
    user=Depends(require_permission("copilot:query")),
):
    return await generate_incident_report(incident_id, user["organization_id"], "executive")


@router.get("/incidents/{incident_id}/technical-report", response_model=CopilotReportResponse)
async def incident_technical_report_endpoint(
    incident_id: str,
    user=Depends(require_permission("copilot:query")),
):
    return await generate_incident_report(incident_id, user["organization_id"], "technical")


@router.get(
    "/attack-chains/{chain_id}/recommended-actions",
    response_model=CopilotAnswerResponse,
)
async def attack_chain_recommended_actions_endpoint(
    chain_id: str,
    user=Depends(require_permission("copilot:query")),
):
    return await recommend_attack_chain_actions(chain_id, user["organization_id"])
