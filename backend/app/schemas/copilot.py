from pydantic import Field

from app.schemas.base import APIModel


class CopilotQuery(APIModel):
    query: str = Field(min_length=1, max_length=2000)
