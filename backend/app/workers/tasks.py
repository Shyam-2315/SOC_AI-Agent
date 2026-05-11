import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from celery.utils.log import get_task_logger

from app.services.ingestion import (
    mark_alert_job_failed,
    mark_alert_job_retrying,
    process_alert_job,
)
from app.workers.celery_app import celery_app


logger = get_task_logger(__name__)
T = TypeVar("T")

_worker_loop: asyncio.AbstractEventLoop | None = None


def _run_async(awaitable: Awaitable[T]) -> T:
    global _worker_loop

    if _worker_loop is None or _worker_loop.is_closed():
        _worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_worker_loop)

    return _worker_loop.run_until_complete(awaitable)


@celery_app.task(
    bind=True,
    name="app.workers.tasks.process_alert_job",
    max_retries=3,
)
def process_alert_job_task(self, alert_context: dict) -> dict:
    task_id = self.request.id
    try:
        return _run_async(process_alert_job(alert_context, task_id))
    except Exception as exc:
        logger.exception("alert processing task failed")
        if self.request.retries < self.max_retries:
            _run_async(
                mark_alert_job_retrying(
                    task_id=task_id,
                    organization_id=alert_context["organization_id"],
                    error=str(exc),
                )
            )
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))

        _run_async(
            mark_alert_job_failed(
                task_id=task_id,
                organization_id=alert_context["organization_id"],
                error=str(exc),
            )
        )
        raise
