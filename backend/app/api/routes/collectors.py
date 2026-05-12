from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    Pagination,
    collector_token_header,
    ingestion_rate_limit,
    pagination_params,
    require_permission,
)
from app.schemas.collector import CollectorCreate, CollectorIngestBatch, CollectorUpdate
from app.services.collectors import (
    authenticate_collector_token,
    create_collector,
    delete_collector,
    ingest_collector_batch,
    list_collectors,
    update_collector,
)


router = APIRouter(tags=["Collectors"])

management_router = APIRouter(prefix="/collectors")
ingestion_router = APIRouter(prefix="/collector")


@management_router.post("", status_code=status.HTTP_201_CREATED)
async def create_collector_endpoint(
    collector: CollectorCreate,
    user=Depends(require_permission("collectors:write")),
):
    return await create_collector(collector, user)


@management_router.get("")
async def list_collectors_endpoint(
    pagination: Pagination = Depends(pagination_params),
    user=Depends(require_permission("collectors:read")),
):
    return await list_collectors(user["organization_id"], pagination)


@management_router.patch("/{collector_id}")
async def update_collector_endpoint(
    collector_id: str,
    update: CollectorUpdate,
    user=Depends(require_permission("collectors:write")),
):
    return await update_collector(collector_id, update, user)


@management_router.delete("/{collector_id}")
async def delete_collector_endpoint(
    collector_id: str,
    user=Depends(require_permission("collectors:write")),
):
    return await delete_collector(collector_id, user)


@ingestion_router.post("/ingest")
async def ingest_collector_batch_endpoint(
    batch: CollectorIngestBatch,
    token: str = Depends(collector_token_header),
    _: None = Depends(ingestion_rate_limit),
):
    collector = await authenticate_collector_token(token)
    return await ingest_collector_batch(batch, collector)


router.include_router(management_router)
router.include_router(ingestion_router)
