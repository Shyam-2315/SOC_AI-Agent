from fastapi import (
    APIRouter,
    Depends
)

from pydantic import BaseModel

from core.dependencies import (
    get_current_user
)

from ai.copilot import (
    process_soc_query
)


router = APIRouter(
    prefix="/copilot",
    tags=["AI Copilot"]
)


class CopilotQuery(BaseModel):

    query: str


@router.post("/query")
async def ask_copilot(
    data: CopilotQuery,
    user=Depends(get_current_user)
):

    result = await process_soc_query(
        data.query,
        user["organization_id"],
    )

    return result
