from __future__ import annotations

import os
from typing import List, Optional

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from evidence.models import ValidationRun
from ..core.dependencies import get_current_user
from ..services.scope_authorization import ScopeAuthorizationError, require_authorized_target
from ..tasks.security_scan import validate_finding_task

router = APIRouter()

ALLOWED_TYPES = {'url', 'ip', 'api'}
ALLOWED_PROFILES = {'quick', 'full', 'custom'}


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


class ValidationOut(BaseModel):
    id: str
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


@sync_to_async
def _serialize(v: ValidationRun):
    return ValidationOut(
        id=str(v.id), target_type=v.target_type, target_value=v.target_value,
        profile=v.profile, engines=v.engines, scope=v.scope, status=v.status,
        progress=v.progress, current_phase=v.current_phase,
        created_at=v.created_at.isoformat(),
        audit_note=f'Scope={v.scope} authorized={v.authorized}',
    )


@sync_to_async
def _create(body: ValidationCreate, user_id: str):
    v = ValidationRun.objects.create(
        user_id=user_id,
        target_type=body.target_type,
        target_value=body.target_value.strip(),
        scope=(body.scope or body.target_value).strip(),
        profile=body.profile,
        engines=body.engines,
        authorized=True,
    )
    task = validate_finding_task.delay(str(v.id))
    v.celery_task_id = task.id
    v.save(update_fields=['celery_task_id'])
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
    if not body.engines or any(engine != 'nmap' for engine in body.engines):
        raise HTTPException(status_code=400, detail='Only the real nmap engine is enabled in this execution phase')
    try:
        require_authorized_target(target)
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return await _serialize(await _create(body, str(user.get('user_id'))))


@sync_to_async
def _list(user_id: str, limit: int):
    return list(ValidationRun.objects.filter(user_id=user_id).order_by('-created_at')[:limit])


@router.get('/validations', response_model=List[ValidationOut])
async def list_validations(limit: int = Query(20, le=100), user=Depends(get_current_user)):
    return [await _serialize(v) for v in await _list(str(user.get('user_id')), limit)]


@sync_to_async
def _get(vid: str, user_id: str):
    return ValidationRun.objects.filter(id=vid, user_id=user_id).first()


@router.get('/validations/{vid}', response_model=ValidationOut)
async def get_validation(vid: str, user=Depends(get_current_user)):
    v = await _get(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return await _serialize(v)


@router.get('/validations/{vid}/progress')
async def get_validation_progress(vid: str, user=Depends(get_current_user)):
    v = await _get(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return {
        'id': str(v.id), 'status': v.status, 'progress': v.progress,
        'current_phase': v.current_phase, 'celery_task_id': v.celery_task_id,
        'created_at': v.created_at.isoformat(),
        'completed_at': v.completed_at.isoformat() if v.completed_at else None,
        'error_message': v.error_message,
    }


@sync_to_async
def _cancel(vid: str, user_id: str):
    v = ValidationRun.objects.filter(id=vid, user_id=user_id).first()
    if not v:
        return None
    if v.status in {ValidationRun.Status.COMPLETED, ValidationRun.Status.FAILED, ValidationRun.Status.CANCELLED}:
        return v
    v.status = ValidationRun.Status.CANCELLED
    v.save(update_fields=['status'])
    if v.celery_task_id:
        from celery.result import AsyncResult
        AsyncResult(v.celery_task_id).revoke(terminate=False)
    return v


@router.post('/validations/{vid}/cancel')
async def cancel_validation(vid: str, user=Depends(get_current_user)):
    v = await _cancel(vid, str(user.get('user_id')))
    if not v:
        raise HTTPException(status_code=404, detail='Validation not found')
    return {'status': v.status}


@router.post('/validations/{vid}/pause')
async def pause_validation(vid: str, user=Depends(get_current_user)):
    raise HTTPException(status_code=409, detail='Pause is not supported by the real Nmap worker; cancel and start a new authorized run instead.')


@router.post('/validations/{vid}/resume')
async def resume_validation(vid: str, user=Depends(get_current_user)):
    raise HTTPException(status_code=409, detail='Resume is not supported by the real Nmap worker; start a new authorized run instead.')
