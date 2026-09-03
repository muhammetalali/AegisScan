from __future__ import annotations

import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from ..contracts import UnifiedValidationOut
from ..core.dependencies import get_current_user
from evidence.models import ValidationRun

router = APIRouter()


@router.get('/validation-contract')
async def get_validation_contract(user=Depends(get_current_user)):
    return {
        'contract_version': '1.0',
        'name': 'unified-validation-engine',
        'source': 'postgresql',
        'resource': '/api/v1/validations',
        'operations': {
            'create': {'method': 'POST', 'path': '/api/v1/validations'},
            'get': {'method': 'GET', 'path': '/api/v1/validations/{validation_id}'},
            'progress': {'method': 'GET', 'path': '/api/v1/validations/{validation_id}/progress'},
            'compliance': {'method': 'GET', 'path': '/api/v1/validations/{validation_id}/compliance'},
            'contract': {'method': 'GET', 'path': '/api/v1/validations/{validation_id}/contract'},
        },
        'response_schema': UnifiedValidationOut.model_json_schema(),
    }


@sync_to_async
def _get_validation(validation_id: str, user_id: str):
    return ValidationRun.objects.filter(id=validation_id, user_id=user_id).first()


@router.get('/validations/{validation_id}/contract', response_model=UnifiedValidationOut)
async def get_validation_contract_snapshot(validation_id: str, user=Depends(get_current_user)):
    validation = await _get_validation(validation_id, str(user.get('user_id')))
    if not validation:
        raise HTTPException(status_code=404, detail='Validation not found')
    return UnifiedValidationOut(
        id=str(validation.id),
        finding_id=str(validation.finding_id) if validation.finding_id else None,
        target_type=validation.target_type,
        target_value=validation.target_value,
        profile=validation.profile,
        engines=list(validation.engines or []),
        scope=validation.scope,
        status=validation.status,
        progress=validation.progress,
        current_phase=validation.current_phase,
        created_at=validation.created_at.isoformat(),
        audit_note=f'Scope={validation.scope} authorized={validation.authorized} finding_id={validation.finding_id or ""}',
    )
