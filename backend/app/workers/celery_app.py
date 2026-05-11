from celery import Celery

from app.core.config import settings


celery_app = Celery(
    "ai_soc_platform",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_default_queue=settings.celery_task_default_queue,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)

# Import task modules so registration is explicit for both the API process
# and standalone Celery workers.
import app.workers.tasks  # noqa: E402,F401
