from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.schemas.copilot import CopilotQuery
from app.services.copilot import ask_copilot


router = APIRouter(
    prefix="/copilot",
    tags=["AI Copilot"],
)


@router.post("/query")
async def ask_copilot_endpoint(
    data: CopilotQuery,
    user=Depends(require_permission("copilot:query")),
):
    return await ask_copilot(data.query, user["organization_id"])
