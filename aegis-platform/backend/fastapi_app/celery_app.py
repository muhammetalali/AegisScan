import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE','django_project.settings')
import django
django.setup()
from celery import Celery
from .core.config import settings

celery_app=Celery('aegisscan',broker=settings.CELERY_BROKER_URL,backend=settings.CELERY_RESULT_BACKEND)
celery_app.conf.update(task_serializer='json',accept_content=['json'],result_serializer='json',timezone='UTC',enable_utc=True,beat_schedule={
    'evaluate-action-slas-every-minute':{'task':'fastapi_app.tasks.workflow_tasks.evaluate_action_slas','schedule':60.0},
    'dispatch-due-enterprise-schedules-every-minute':{'task':'enterprise.dispatch_due_schedules','schedule':60.0},
})
celery_app.autodiscover_tasks(['fastapi_app.tasks','enterprise'])
