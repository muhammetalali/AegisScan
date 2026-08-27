from celery import Celery

from .core.config import settings

celery_app = Celery(
    "aegisscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "fastapi_app.tasks.workflow_tasks",
        "fastapi_app.tasks.report_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

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
