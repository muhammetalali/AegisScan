import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django

django.setup()

from celery import Celery

from .core.config import settings


celery_app = Celery(
    "aegisscan",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

SCANNER_QUEUE = "scanners"
SCANNER_TASK_ROUTES = {
    "fastapi_app.tasks.security_scan.run_nmap_scan": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.security_scan.run_nuclei_scan": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.security_scan.validate_finding_task": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.advanced_scans.run_masscan_scan": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.advanced_scans.run_semgrep_scan": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.native_capabilities.run_native_capability_scan": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.finding_validation.validate_finding_e2e": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.nmap_finding_validation.validate_nmap_finding_e2e": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.offensive_validation_tasks.validate_offensive_finding": {"queue": SCANNER_QUEUE},
    "fastapi_app.tasks.reliability_probe.scanner_worker_loss_probe": {"queue": SCANNER_QUEUE},
}

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_default_queue="default",
    task_routes=SCANNER_TASK_ROUTES,
    broker_transport_options={"visibility_timeout": settings.CELERY_VISIBILITY_TIMEOUT_SECONDS},
    result_backend_transport_options={"visibility_timeout": settings.CELERY_VISIBILITY_TIMEOUT_SECONDS},
    visibility_timeout=settings.CELERY_VISIBILITY_TIMEOUT_SECONDS,
    imports=(
        "fastapi_app.tasks.advanced_scans",
        "fastapi_app.tasks.native_capabilities",
        "fastapi_app.tasks.finding_validation",
        "fastapi_app.tasks.nmap_finding_validation",
        "fastapi_app.tasks.offensive_validation_tasks",
        "fastapi_app.tasks.reliability_probe",
        "fastapi_app.tasks.security_scan",
        "fastapi_app.tasks.workflow_tasks",
        "enterprise.tasks",
    ),
    beat_schedule={
        "evaluate-action-slas-every-minute": {
            "task": "fastapi_app.tasks.workflow_tasks.evaluate_action_slas",
            "schedule": 60.0,
        },
        "dispatch-due-enterprise-schedules-every-minute": {
            "task": "enterprise.dispatch_due_schedules",
            "schedule": 60.0,
        },
        "dispatch-report-delivery-outbox-every-minute": {
            "task": "enterprise.dispatch_report_deliveries",
            "schedule": 60.0,
        },
        "dispatch-notification-delivery-outbox-every-minute": {
            "task": "enterprise.dispatch_notification_deliveries",
            "schedule": 60.0,
        },
        "expire-report-artifacts-hourly": {
            "task": "enterprise.expire_report_exports",
            "schedule": 3600.0,
        },
    },
)
