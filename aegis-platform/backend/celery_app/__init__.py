from celery import Celery
from celery.schedules import crontab
import os

celery_app = Celery("aegis")

celery_app.conf.update(
    broker_url=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    result_backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0"),
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    beat_schedule={
        "check-scheduled-scans": {
            "task": "celery_app.tasks.check_scheduled_scans",
            "schedule": crontab(minute="*/5"),
        },
        "generate-scheduled-reports": {
            "task": "celery_app.tasks.generate_scheduled_reports",
            "schedule": crontab(minute=0, hour=2),
        },
        "cleanup-old-scans": {
            "task": "celery_app.tasks.cleanup_old_scans",
            "schedule": crontab(minute=0, hour=3),
        },
        "update-security-posture": {
            "task": "celery_app.tasks.update_all_postures",
            "schedule": crontab(minute=0, hour=4),
        },
        "send-notification-digests": {
            "task": "celery_app.tasks.send_notification_digests",
            "schedule": crontab(minute=0, hour=8),
        },
        "backup-database": {
            "task": "celery_app.tasks.backup_database",
            "schedule": crontab(minute=0, hour=3),
        },
        "check-service-health": {
            "task": "celery_app.tasks.check_service_health",
            "schedule": crontab(minute="*/1"),
        },
        "sync-external-intelligence": {
            "task": "celery_app.tasks.sync_external_intelligence",
            "schedule": crontab(minute=0, hour=1),
        },
    },
    imports=(
        "celery_app.tasks.scan_tasks",
        "celery_app.tasks.report_tasks",
        "celery_app.tasks.notification_tasks",
        "celery_app.tasks.maintenance_tasks",
    ),
)

# Auto-discover tasks
celery_app.autodiscover_tasks([
    "celery_app.tasks",
])