from fastapi import APIRouter, Depends

from app.api.dependencies import get_collector_organization_id
from app.schemas.log import LogModel
from app.services.ingestion import get_alert_job_status, ingest_log


router = APIRouter(
    prefix="/ingest",
    tags=["Log Ingestion"],
)


@router.post("/")
async def ingest_log_endpoint(
    data: LogModel,
    organization_id: str = Depends(get_collector_organization_id),
):
    return await ingest_log(data, organization_id)


@router.post("/async")
async def ingest_log_async_endpoint(
    data: LogModel,
    organization_id: str = Depends(get_collector_organization_id),
):
    return await ingest_log(
        data,
        organization_id,
        force_background=True,
    )


@router.get("/tasks/{task_id}")
async def get_alert_job_status_endpoint(
    task_id: str,
    organization_id: str = Depends(get_collector_organization_id),
):
    return await get_alert_job_status(task_id, organization_id)
