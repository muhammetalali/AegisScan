from celery import Celery

from .core.config import settings
from .services import celery_monitoring  # noqa: F401 - register Celery signals

celery_app = Celery(
    "aegisscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "fastapi_app.tasks.workflow_tasks",
        "fastapi_app.tasks.report_tasks",
        "fastapi_app.tasks.health_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,
    result_expires=86400,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    beat_schedule={
        "evaluate-action-slas-every-minute": {
            "task": "fastapi_app.tasks.workflow_tasks.evaluate_action_slas",
            "schedule": 60.0,
        },
        "generate-scheduled-reports": {
            "task": "fastapi_app.tasks.report_tasks.generate_scheduled_reports",
            "schedule": 60.0,
        },
    },
)
