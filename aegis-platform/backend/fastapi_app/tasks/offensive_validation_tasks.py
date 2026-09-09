from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from celery import shared_task

from django_project.evidence.models import Evidence, ValidationRun
from fastapi_app.services.offensive_validation import ENGINE, run_offensive_validation


_TERMINAL = {
    ValidationRun.Status.COMPLETED,
    ValidationRun.Status.FAILED,
    ValidationRun.Status.CANCELLED,
}


def _terminal_payload(validation: ValidationRun, *, redelivered: bool = False) -> dict[str, Any]:
    result = dict(validation.result) if isinstance(validation.result, dict) else {}
    payload: dict[str, Any] = {
        'status': validation.status,
        'validation_id': str(validation.id),
        'finding_id': str(validation.finding_id) if validation.finding_id else None,
        'engine': ENGINE,
        'redelivered': redelivered,
    }
    if result:
        payload.update(result)
        payload['redelivered'] = redelivered
    return payload


@shared_task(
    bind=True,
    name='fastapi_app.tasks.offensive_validation_tasks.validate_offensive_finding',
    max_retries=0,
)
def validate_offensive_finding(self, validation_id: str) -> dict[str, Any]:
    """Run AegisScan offensive validation from a queued ValidationRun.

    The task is the product integration point: API creates a bound ValidationRun,
    Celery executes the existing validation service, and the service persists the
    deterministic Evidence record linked to the Finding.
    """
    validation = ValidationRun.objects.select_related(
        'finding',
        'finding__asset',
        'finding__scan',
        'user',
    ).get(pk=validation_id)

    if validation.engines != [ENGINE]:
        raise ValueError(f'ValidationRun engines must be exactly [{ENGINE!r}]')
    if validation.finding_id is None:
        raise ValueError('Offensive validation requires a finding-bound ValidationRun')
    if validation.status in _TERMINAL:
        evidence_id = (validation.result or {}).get('evidence_id') if isinstance(validation.result, dict) else None
        if validation.status == ValidationRun.Status.COMPLETED and evidence_id:
            if Evidence.objects.filter(pk=evidence_id, finding_id=validation.finding_id, source=ENGINE).exists():
                return _terminal_payload(validation, redelivered=True)
        if validation.status != ValidationRun.Status.COMPLETED:
            return _terminal_payload(validation, redelivered=True)

    try:
        return run_offensive_validation(
            finding=validation.finding,
            actor=validation.user,
            profile=validation.profile or 'standard',
            validation_run=validation,
        )
    except Exception as exc:
        validation = ValidationRun.objects.filter(pk=validation_id).first()
        if validation and validation.status not in _TERMINAL:
            validation.status = ValidationRun.Status.FAILED
            validation.progress = 100
            validation.current_phase = 'failed'
            validation.error_message = f'{type(exc).__name__}: offensive validation task failed'
            validation.completed_at = datetime.now(timezone.utc)
            validation.save(update_fields=['status', 'progress', 'current_phase', 'error_message', 'completed_at'])
        raise
