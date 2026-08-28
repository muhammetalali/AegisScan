from celery import Celery
from celery.signals import task_failure

from .core.config import settings
from .services import celery_monitoring  # noqa: F401 - register Celery signals
from .services.task_reliability import enqueue_dead_letter

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

redis_tls = settings.CELERY_BROKER_URL.startswith("rediss://")
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
    task_default_queue="default",
    task_default_exchange="aegis",
    task_default_exchange_type="direct",
    task_default_routing_key="default",
    task_queues={
        "default": {"exchange": "aegis", "routing_key": "default"},
        "workflow": {"exchange": "aegis", "routing_key": "workflow"},
        "reports": {"exchange": "aegis", "routing_key": "reports"},
        "health": {"exchange": "aegis", "routing_key": "health"},
    },
    task_routes={
        "fastapi_app.tasks.workflow_tasks.*": {"queue": "workflow", "routing_key": "workflow"},
        "fastapi_app.tasks.report_tasks.*": {"queue": "reports", "routing_key": "reports"},
        "fastapi_app.tasks.health_tasks.*": {"queue": "health", "routing_key": "health"},
    },
    task_annotations={
        "fastapi_app.tasks.workflow_tasks.*": {"rate_limit": "30/m"},
        "fastapi_app.tasks.report_tasks.*": {"rate_limit": "10/m"},
    },
    beat_schedule={
        "evaluate-action-slas-every-minute": {
            "task": "fastapi_app.tasks.workflow_tasks.evaluate_action_slas",
            "schedule": 60.0,
            "options": {"queue": "workflow", "routing_key": "workflow"},
        },
        "generate-scheduled-reports": {
            "task": "fastapi_app.tasks.report_tasks.generate_scheduled_reports",
            "schedule": 60.0,
            "options": {"queue": "reports", "routing_key": "reports"},
        },
    },
)

if redis_tls:
    celery_app.conf.update(
        broker_use_ssl={"ssl_cert_reqs": settings.REDIS_SSL_CERT_REQS},
        redis_backend_use_ssl={"ssl_cert_reqs": settings.REDIS_SSL_CERT_REQS},
    )


@task_failure.connect(weak=False)
def route_failed_task_to_dlq(task_id=None, task=None, args=None, kwargs=None, exception=None, **_):
    if not task_id or not task:
        return
    retries = getattr(getattr(task, "request", None), "retries", 0)
    max_retries = getattr(task, "max_retries", 0)
    if max_retries is None or retries < max_retries:
        return
    try:
        enqueue_dead_letter(task.name, task_id, args or (), kwargs or {}, str(exception or "unknown error"))
    except Exception:
        pass
