from __future__ import annotations

from celery import shared_task
from django.db import transaction

from django_project.projects.models import ScheduledScanExecution

from fastapi_app.services.scheduled_execution import (
    claim_due_schedule,
    due_schedule_ids,
    execute_scheduled_occurrence,
    retryable_execution_ids,
)


@shared_task(
    bind=True,
    name='fastapi_app.tasks.scheduled_scans.run_scheduled_scan_execution',
    max_retries=2,
    default_retry_delay=30,
)
def run_scheduled_scan_execution(self, execution_id: str):
    return execute_scheduled_occurrence(execution_id)


@shared_task(name='fastapi_app.tasks.scheduled_scans.dispatch_due_scheduled_scans')
def dispatch_due_scheduled_scans(limit: int = 100):
    bounded = max(1, min(int(limit), 500))
    execution_ids: list[str] = []
    claim_errors: list[dict[str, str]] = []

    for schedule_id in due_schedule_ids(limit=bounded):
        try:
            execution, _created = claim_due_schedule(schedule_id)
        except Exception as exc:
            claim_errors.append({'schedule_id': schedule_id, 'error': str(exc)[:500]})
            continue
        if execution is not None:
            execution_ids.append(str(execution.id))

    for execution_id in retryable_execution_ids(limit=bounded):
        if execution_id not in execution_ids:
            execution_ids.append(execution_id)

    queued: list[dict[str, str]] = []
    enqueue_errors: list[dict[str, str]] = []
    for execution_id in execution_ids[:bounded]:
        task_id = f'scheduled-execution-{execution_id}'
        try:
            result = run_scheduled_scan_execution.apply_async(
                args=[execution_id],
                task_id=task_id,
            )
            with transaction.atomic():
                execution = ScheduledScanExecution.objects.select_for_update().get(pk=execution_id)
                if execution.status not in {
                    ScheduledScanExecution.Status.DISPATCHED,
                    ScheduledScanExecution.Status.BLOCKED,
                }:
                    execution.celery_task_id = result.id
                    execution.save(update_fields=['celery_task_id', 'updated_at'])
            queued.append({'execution_id': execution_id, 'task_id': result.id})
        except Exception as exc:
            with transaction.atomic():
                execution = ScheduledScanExecution.objects.select_for_update().get(pk=execution_id)
                if execution.status not in {
                    ScheduledScanExecution.Status.DISPATCHED,
                    ScheduledScanExecution.Status.BLOCKED,
                }:
                    execution.status = ScheduledScanExecution.Status.FAILED
                    execution.reason = f'Scheduled execution enqueue failed: {exc}'[:4000]
                    execution.save(update_fields=['status', 'reason', 'updated_at'])
            enqueue_errors.append({'execution_id': execution_id, 'error': str(exc)[:500]})

    return {
        'claimed_or_retryable': len(execution_ids),
        'queued': len(queued),
        'deliveries': queued,
        'claim_errors': claim_errors,
        'enqueue_errors': enqueue_errors,
    }


__all__ = [
    'dispatch_due_scheduled_scans',
    'run_scheduled_scan_execution',
]
