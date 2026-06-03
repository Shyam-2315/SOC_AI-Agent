from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.schemas.ai_copilot import (
    AlertTriageResponse,
    CopilotQueryRequest,
    CopilotQueryResponse,
    FalsePositiveScoreResponse,
    IncidentSummaryResponse,
    RecommendedActionsResponse,
)
from app.services.ai_copilot_service import (
    interpret_soc_query,
    recommend_actions_for_incident,
    score_false_positive,
    summarize_incident,
    triage_alert,
)


router = APIRouter(
    prefix="/api/ai",
    tags=["AI Copilot"],
)


@router.get("/alerts/{alert_id}/triage", response_model=AlertTriageResponse)
async def triage_alert_endpoint(
    alert_id: str,
    user=Depends(require_permission("alerts:read")),
):
    return await triage_alert(alert_id, user["organization_id"])


@router.get(
    "/alerts/{alert_id}/false-positive-score",
    response_model=FalsePositiveScoreResponse,
)
async def false_positive_score_endpoint(
    alert_id: str,
    user=Depends(require_permission("alerts:read")),
):
    return await score_false_positive(alert_id, user["organization_id"])


@router.get("/incidents/{incident_id}/summary", response_model=IncidentSummaryResponse)
async def incident_summary_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    return await summarize_incident(incident_id, user["organization_id"])


@router.get(
    "/incidents/{incident_id}/recommended-actions",
    response_model=RecommendedActionsResponse,
)
async def recommended_actions_endpoint(
    incident_id: str,
    user=Depends(require_permission("incidents:read")),
):
    return await recommend_actions_for_incident(incident_id, user["organization_id"])


@router.post("/copilot/query", response_model=CopilotQueryResponse)
async def copilot_query_endpoint(
    data: CopilotQueryRequest,
    user=Depends(require_permission("copilot:query")),
):
    return await interpret_soc_query(data.query, user["organization_id"])
