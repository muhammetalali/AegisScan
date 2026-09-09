from __future__ import annotations

import os
from typing import Any, List, Optional
from uuid import UUID

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from evidence.models import Evidence, ValidationRun
from vulnerabilities.models import Vulnerability
from ..core.dependencies import get_current_user
from ..services.scope_authorization import ScopeAuthorizationError, require_authorized_target
from ..services.authorization_guard import current_asset_authorization
from ..services.offensive_validation import ENGINE as OFFENSIVE_ENGINE
from ..services.offensive_validation import _authorization_scope_url, _candidate_url
from ..tasks.finding_validation import validate_finding_e2e
from ..tasks.nmap_finding_validation import validate_nmap_finding_e2e
from ..tasks.offensive_validation_tasks import validate_offensive_finding

router = APIRouter()

ALLOWED_TYPES = {'url', 'ip', 'api'}
ALLOWED_PROFILES = {'quick', 'full', 'custom'}
OFFENSIVE_PROFILES = {'quick', 'standard', 'full'}


class ValidationCreate(BaseModel):
    target_type: str = Field(description='url | ip | api')
    target_value: str
    profile: str = 'full'
    engines: List[str] = Field(default_factory=lambda: ['nmap'])
    scope: Optional[str] = None
    authorized: bool = False
    include_subdomains: bool = False
    duration_minutes: int = 60
    rate_limit: int = 5
    extra: dict = Field(default_factory=dict)
    finding_id: Optional[UUID] = None


class OffensiveValidationCreate(BaseModel):
    finding_id: UUID
    profile: str = 'standard'
    authorized: bool = True


class ValidationOut(BaseModel):
    id: str
    finding_id: Optional[str] = None
    target_type: str
    target_value: str
    profile: str
    engines: List[str]
    scope: str
    status: str
    progress: int
    current_phase: str
    created_at: str
    audit_note: str
    authorization_decision_id: Optional[str] = None
    celery_task_id: Optional[str] = None
    completed_at: Optional[str] = None


class ValidationResultOut(BaseModel):
    id: str
    finding_id: Optional[str]
    status: str
    progress: int
    current_phase: str
    celery_task_id: str
    result: dict[str, Any]
    error_message: str
    created_at: str
    completed_at: Optional[str] = None


class ValidationEvidenceOut(BaseModel):
    id: str
    finding_id: Optional[str]
    source: str
    evidence_type: str
    sha256: str
    metadata: dict[str, Any]
    collected_at: str


@sync_to_async
def _serialize(v: ValidationRun):
    return ValidationOut(
        id=str(v.id),
        finding_id=str(v.finding_id) if v.finding_id else None,
        target_type=v.target_type, target_value=v.target_value,
        profile=v.profile, engines=v.engines, scope=v.scope, status=v.status,
        progress=v.progress, current_phase=v.current_phase,
        created_at=v.created_at.isoformat(),
        audit_note=f'Scope={v.scope} authorized={v.authorized} finding_id={v.finding_id or ""}',
        authorization_decision_id=str(v.authorization_decision_id) if v.authorization_decision_id else None,
        celery_task_id=v.celery_task_id or None,
        completed_at=v.completed_at.isoformat() if v.completed_at else None,
    )


@sync_to_async
def _get_finding(finding_id: UUID, user_id: str):
    return Vulnerability.objects.filter(id=finding_id).filter(
        project__owner_id=user_id,
    ).select_related('asset', 'scan').first() or Vulnerability.objects.filter(
        id=finding_id, project__members__id=user_id,
    ).select_related('asset', 'scan').first()


@sync_to_async
def _create(body: ValidationCreate, user_id: str, finding: Optional[Vulnerability]):
    if not finding:
        raise ValueError('finding_id is required for real validation execution')
    if not finding.asset_id:
        raise ValueError('Finding must reference a persisted asset')
    decision, reason = current_asset_authorization(finding.asset, body.target_value)
    if decision is None:
        raise PermissionError(reason)
    v = ValidationRun.objects.create(
        user_id=user_id,
        finding=finding,
        target_type=body.target_type,
        target_value=body.target_value.strip(),
        scope=(body.scope or body.target_value).strip(),
        profile=body.profile,
        engines=body.engines,
        authorized=True,
        authorization_decision=decision,
    )
    source_engine = (finding.source_engine or '').strip().lower()
    task = validate_nmap_finding_e2e if source_engine == 'nmap' else validate_finding_e2e
    task_result = task.delay(str(v.id))
    v.celery_task_id = task_result.id
    v.save(update_fields=['celery_task_id'])
    return v


@sync_to_async
def _create_offensive(body: OffensiveValidationCreate, user_id: str, finding: Optional[Vulnerability]):
    if not finding:
        raise ValueError('finding_id is required for offensive validation')
    if not finding.asset_id or not finding.scan_id:
        raise ValueError('Finding must reference a persisted asset and scan')
    target_url = _candidate_url(finding)
    decision, reason = current_asset_authorization(finding.asset, target_url)
    if decision is None:
        raise PermissionError(reason)
    if _authorization_scope_url(target_url) != _authorization_scope_url(decision.target_snapshot):
        raise PermissionError('Finding target does not match the current authorized asset endpoint')
    v = ValidationRun.objects.create(
        user_id=user_id,
        finding=finding,
        target_type='url',
        target_value=decision.target_snapshot,
        scope=str(finding.project_id),
        profile=body.profile,
        engines=[OFFENSIVE_ENGINE],
        authorized=True,
        authorization_decision=decision,
        current_phase='queued',
    )
    task_result = validate_offensive_finding.delay(str(v.id))
    v.celery_task_id = task_result.id
    v.save(update_fields=['celery_task_id'])
    v.refresh_from_db()
    return v


@router.post('/validations', response_model=ValidationOut, status_code=201)
async def create_validation(body: ValidationCreate, user=Depends(get_current_user)):
    if body.target_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail=f'target_type must be one of {sorted(ALLOWED_TYPES)}')
    if body.profile not in ALLOWED_PROFILES:
        raise HTTPException(status_code=400, detail=f'profile must be one of {sorted(ALLOWED_PROFILES)}')
    if not body.authorized:
        raise HTTPException(status_code=400, detail='authorized must be true for real security execution')
    target = (body.scope or body.target_value).strip()
    if not target:
        raise HTTPException(status_code=400, detail='target_value is required')
    if not body.finding_id:
        raise HTTPException(status_code=400, detail='finding_id is required for real validation execution')

    user_id = str(user.get('user_id'))
    finding = await _get_finding(body.finding_id, user_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    source_engine = (finding.source_engine or '').strip().lower()
    if source_engine not in {'nmap', 'nuclei'}:
        raise HTTPException(status_code=400, detail=f'Finding source engine is not supported for validation: {source_engine}')
    if len(body.engines) != 1 or body.engines[0].lower() != source_engine:
        raise HTTPException(status_code=400, detail=f'Finding validation engine must be {source_engine}')
    if body.engines[0].lower() == 'nuclei':
        asset_url = ((finding.asset.configuration or {}).get('url') if finding.asset else None)
        if not asset_url:
            raise HTTPException(status_code=400, detail='Finding asset has no URL for Nuclei validation')
        if body.target_value.strip() != asset_url.strip():
            raise HTTPException(status_code=400, detail='Finding validation target must exactly match the finding asset URL')
    else:
        asset_host = ((finding.asset.configuration or {}).get('host') or (finding.asset.configuration or {}).get('ip') or (finding.asset.configuration or {}).get('domain')) if finding.asset else None
        if not asset_host:
            raise HTTPException(status_code=400, detail='Finding asset has no host/ip/domain for Nmap validation')
        if body.target_value.strip() != str(asset_host).strip():
            raise HTTPException(status_code=400, detail='Finding validation target must exactly match the finding asset host')

    try:
        require_authorized_target(target)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    try:
        validation = await _create(body, user_id, finding)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await _serialize(validation)


@router.post('/validations/offensive', response_model=ValidationOut, status_code=201)
async def create_offensive_validation(body: OffensiveValidationCreate, user=Depends(get_current_user)):
    if body.profile not in OFFENSIVE_PROFILES:
        raise HTTPException(status_code=400, detail=f'profile must be one of {sorted(OFFENSIVE_PROFILES)}')
    if not body.authorized:
        raise HTTPException(status_code=400, detail='authorized must be true for offensive validation execution')
    user_id = str(user.get('user_id'))
    finding = await _get_finding(body.finding_id, user_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    try:
        target_url = _candidate_url(finding)
        require_authorized_target(_authorization_scope_url(target_url), url=True)
        validation = await _create_offensive(body, user_id, finding)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return await _serialize(validation)


@sync_to_async
def _list(user_id: str, limit: int):
    return list(ValidationRun.objects.filter(user_id=user_id).order_by('-created_at')[:limit])


@router.get('/validations', response_model=List[ValidationOut])
async def list_validations(limit: int = Query(20, le=100), user=Depends(get_current_user)):
    return [await _serialize(v) for v in await _list(str(user.get('user_id')), limit)]


@sync_to_async
def _get(vid: UUID, user_id: str):
    return ValidationRun.objects.filter(id=vid, user_id=user_id).first()


@sync_to_async
def _get_result(vid: UUID, user_id: str):
    v = ValidationRun.objects.filter(id=vid, user_id=user_id).first()
    if not v:
        return None
    return ValidationResultOut(
        id=str(v.id),
        finding_id=str(v.finding_id) if v.finding_id else None,
        status=v.status,
        progress=v.progress,
        current_phase=v.current_phase,
        celery_task_id=v.celery_task_id or '',
        result=v.result if isinstance(v.result, dict) else {},
        error_message=v.error_message or '',
        created_at=v.created_at.isoformat(),
        completed_at=v.completed_at.isoformat() if v.completed_at else None,
    )


@sync_to_async
def _get_validation_evidence(vid: UUID, user_id: str, limit: int):
    v = ValidationRun.objects.filter(id=vid, user_id=user_id).first()
    if not v:
        return None
    rows = []
    for evidence in Evidence.objects.filter(finding_id=v.finding_id).order_by('-collected_at')[:200]:
        metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
        if str(metadata.get('validation_run_id', '')) != str(v.id):
            continue
        rows.append(ValidationEvidenceOut(
            id=str(evidence.id),
            finding_id=str(evidence.finding_id) if evidence.finding_id else None,
            source=evidence.source,
            evidence_type=evidence.evidence_type,
            sha256=evidence.sha256,
            metadata=metadata,
            collected_at=evidence.collected_at.isoformat(),
        ))
        if len(rows) >= limit:
            break
    return rows


@router.get('/validations/{vid}', response_model=ValidationOut)
async def get_validation(vid: UUID, user=Depends(get_current_user)):
    v = await _get(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return await _serialize(v)


@router.get('/validations/{vid}/result', response_model=ValidationResultOut)
async def get_validation_result(vid: UUID, user=Depends(get_current_user)):
    result = await _get_result(vid, str(user.get('user_id')))
    if not result:
        raise HTTPException(status_code=404, detail='Validation not found')
    return result


@router.get('/validations/{vid}/evidence', response_model=List[ValidationEvidenceOut])
async def get_validation_evidence(vid: UUID, limit: int = Query(50, le=100), user=Depends(get_current_user)):
    evidence = await _get_validation_evidence(vid, str(user.get('user_id')), limit)
    if evidence is None:
        raise HTTPException(status_code=404, detail='Validation not found')
    return evidence


@router.get('/validations/{vid}/progress')
async def get_validation_progress(vid: UUID, user=Depends(get_current_user)):
    v = await _get(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return {
        'id': str(v.id), 'finding_id': str(v.finding_id) if v.finding_id else None,
        'status': v.status, 'progress': v.progress,
        'current_phase': v.current_phase, 'celery_task_id': v.celery_task_id,
        'created_at': v.created_at.isoformat(),
        'completed_at': v.completed_at.isoformat() if v.completed_at else None,
        'error_message': v.error_message,
    }


@sync_to_async
def _cancel(vid: UUID, user_id: str):
    v = ValidationRun.objects.filter(id=vid, user_id=user_id).first()
    if not v:
        return None
    if v.status in {ValidationRun.Status.COMPLETED, ValidationRun.Status.FAILED, ValidationRun.Status.CANCELLED}:
        return v
    v.status = ValidationRun.Status.CANCELLED
    v.progress = 100
    v.current_phase = 'cancelled'
    v.save(update_fields=['status', 'progress', 'current_phase'])
    if v.celery_task_id:
        from celery.result import AsyncResult
        AsyncResult(v.celery_task_id).revoke(terminate=False)
    return v


@router.post('/validations/{vid}/cancel', response_model=ValidationOut)
async def cancel_validation(vid: UUID, user=Depends(get_current_user)):
    v = await _cancel(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return await _serialize(v)
