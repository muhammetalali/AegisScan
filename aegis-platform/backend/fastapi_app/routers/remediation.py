from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from asgiref.sync import sync_to_async
from django.db import transaction
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from django_project.evidence.models import ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from ..core.dependencies import get_current_user
from ..services.scope_authorization import ScopeAuthorizationError, require_authorized_target
from ..tasks.finding_validation import validate_finding_e2e
from ..tasks.nmap_finding_validation import validate_nmap_finding_e2e

router = APIRouter()


class RemediationValidationRequest(BaseModel):
    authorized: bool = False
    profile: str = 'quick'
    duration_minutes: int = Field(default=5, ge=1, le=60)
    rate_limit: int = Field(default=5, ge=1, le=100)
    reason: str = ''


class RemediationValidationConflict(Exception):
    def __init__(self, validation: ValidationRun):
        self.validation = validation
        super().__init__(f'A remediation validation is already running for this finding: {validation.id}')


@sync_to_async
def _get_finding(vuln_id: UUID, user_id: str) -> Optional[Vulnerability]:
    return Vulnerability.objects.select_related('asset', 'scan', 'project').filter(
        id=vuln_id,
        project__owner_id=user_id,
    ).first() or Vulnerability.objects.select_related('asset', 'scan', 'project').filter(
        id=vuln_id,
        project__members__id=user_id,
    ).first()


def _dispatch_validation_task(validation_id: str, engine: str) -> None:
    task = validate_nmap_finding_e2e if engine == 'nmap' else validate_finding_e2e
    result = task.delay(validation_id)
    ValidationRun.objects.filter(pk=validation_id).update(celery_task_id=result.id)


@sync_to_async
def _create_run(
    finding: Vulnerability,
    user_id: str,
    target_type: str,
    target_value: str,
    scope: str,
    profile: str,
    engine: str,
    reason: str,
) -> ValidationRun:
    with transaction.atomic():
        locked_finding = Vulnerability.objects.select_for_update().get(pk=finding.pk)
        active = ValidationRun.objects.filter(
            finding_id=locked_finding.pk,
            user_id=user_id,
            status__in=[ValidationRun.Status.QUEUED, ValidationRun.Status.RUNNING],
        ).order_by('-created_at').first()
        if active:
            raise RemediationValidationConflict(active)

        workflow_result = {'workflow': 'remediation'}
        if reason:
            workflow_result['reason'] = reason
        validation = ValidationRun.objects.create(
            user_id=user_id,
            finding=locked_finding,
            target_type=target_type,
            target_value=target_value,
            scope=scope,
            profile=profile,
            engines=[engine],
            authorized=True,
            current_phase='queued',
            result=workflow_result,
        )
        transaction.on_commit(
            lambda validation_id=str(validation.id), task_engine=engine: _dispatch_validation_task(
                validation_id, task_engine
            )
        )
        return validation


@sync_to_async
def _latest_run(vuln_id: UUID, user_id: str) -> Optional[ValidationRun]:
    return ValidationRun.objects.filter(
        finding_id=vuln_id,
        user_id=user_id,
    ).order_by('-created_at').first()


def _state(validation: Optional[ValidationRun]) -> str:
    if not validation:
        return 'not_requested'
    if validation.status in {ValidationRun.Status.QUEUED, ValidationRun.Status.RUNNING}:
        return 'validating'
    if validation.status == ValidationRun.Status.CANCELLED:
        return 'cancelled'
    if validation.status == ValidationRun.Status.FAILED:
        return 'validation_failed'
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is False:
        return 'verified'
    if result.get('finding_present') is True:
        return 'not_fixed'
    return 'validation_failed'


@router.post('/vulnerabilities/{vuln_id}/remediation/validate', status_code=202)
async def request_remediation_validation(
    vuln_id: UUID,
    body: RemediationValidationRequest,
    user=Depends(get_current_user),
):
    if not body.authorized:
        raise HTTPException(status_code=400, detail='authorized must be true for real remediation validation')

    user_id = str(user.get('user_id'))
    finding = await _get_finding(vuln_id, user_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Vulnerability not found')

    engine = (finding.source_engine or '').strip().lower()
    if engine not in {'nmap', 'nuclei'}:
        raise HTTPException(status_code=400, detail=f'Remediation validation is not supported for engine: {engine or "unknown"}')

    asset_config = (finding.asset.configuration or {}) if finding.asset else {}
    if engine == 'nuclei':
        target = str(asset_config.get('url') or '').strip()
        target_type = 'url'
    else:
        target = str(asset_config.get('host') or asset_config.get('ip') or asset_config.get('domain') or '').strip()
        target_type = 'ip'

    if not target:
        raise HTTPException(status_code=400, detail='Finding asset does not contain the target required by its validation engine')
    if asset_config.get('authorized') is not True:
        raise HTTPException(status_code=403, detail='Execution blocked: finding asset is not explicitly marked authorized.')

    try:
        require_authorized_target(target)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        validation = await _create_run(
            finding=finding,
            user_id=user_id,
            target_type=target_type,
            target_value=target,
            scope=target,
            profile=body.profile,
            engine=engine,
            reason=body.reason.strip(),
        )
    except RemediationValidationConflict as exc:
        raise HTTPException(
            status_code=409,
            detail={
                'message': 'A remediation validation is already running for this finding.',
                'validation_id': str(exc.validation.id),
            },
        ) from exc

    return {
        'workflow': 'remediation',
        'state': 'queued',
        'finding_id': str(vuln_id),
        'validation_id': str(validation.id),
        'engine': engine,
        'target': target,
        'authorized': True,
        'created_at': validation.created_at.astimezone(timezone.utc).isoformat(),
    }


@router.get('/vulnerabilities/{vuln_id}/remediation/status')
async def remediation_status(vuln_id: UUID, user=Depends(get_current_user)):
    user_id = str(user.get('user_id'))
    finding = await _get_finding(vuln_id, user_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    validation = await _latest_run(vuln_id, user_id)
    result: dict[str, Any] = validation.result if validation and isinstance(validation.result, dict) else {}
    return {
        'workflow': 'remediation',
        'state': _state(validation),
        'finding_id': str(vuln_id),
        'validation_status': finding.validation_status,
        'vulnerability_status': finding.status,
        'validation_id': str(validation.id) if validation else None,
        'validation_run_status': validation.status if validation else None,
        'progress': validation.progress if validation else 0,
        'current_phase': validation.current_phase if validation else 'not_requested',
        'celery_task_id': validation.celery_task_id if validation else None,
        'finding_present': result.get('finding_present'),
        'evidence_id': result.get('evidence_id'),
        'completed_at': validation.completed_at.astimezone(timezone.utc).isoformat() if validation and validation.completed_at else None,
        'error_message': validation.error_message if validation else '',
    }
