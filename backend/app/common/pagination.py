from fastapi import Query
from pydantic import BaseModel


class Pagination(BaseModel):
    limit: int
    offset: int


def pagination_params(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Pagination:
    return Pagination(limit=limit, offset=offset)
