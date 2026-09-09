from __future__ import annotations

from typing import Any, Literal

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from django_project.assets.models import Asset

from ..core.dependencies import get_current_user
from ..services.authorization_guard import asset_target
from ..services.capability_registry import get_capability, list_capabilities, validate_capability_options
from ..services.hexstrike_catalog import hexstrike_catalog
from ..tasks.advanced_scans import run_masscan_scan, run_semgrep_scan
from ..tasks.security_scan import run_nmap_scan, run_nuclei_scan
from .scans import ScanCreate, _attach_celery_task, _create_scan, _serialize_scan

router = APIRouter()
_POLICY_VERSION = 'capability-execution.v1'
_TASKS = {
    'nmap': run_nmap_scan,
    'masscan': run_masscan_scan,
    'nuclei': run_nuclei_scan,
    'semgrep': run_semgrep_scan,
}


class CapabilityExecutionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    project_id: str
    asset_id: str
    depth: Literal['quick', 'standard', 'deep', 'comprehensive'] = 'standard'
    options: dict[str, Any] = Field(default_factory=dict)


@sync_to_async
def _asset_for_execution(asset_id: str, project_id: str, user_id: str):
    return (
        Asset.objects.select_related('project')
        .filter(pk=asset_id, project_id=project_id)
        .filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id))
        .distinct()
        .first()
    )


@router.get('/')
async def capabilities(user=Depends(get_current_user)):
    return {
        'policy_version': _POLICY_VERSION,
        'execution_model': 'authorized-asset -> isolated-celery -> evidence -> governance',
        'capabilities': [item.public_dict() for item in list_capabilities()],
    }


@router.get('/upstream/hexstrike')
async def upstream_hexstrike_capabilities(user=Depends(get_current_user)):
    try:
        return hexstrike_catalog()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post('/{capability_id}/execute', status_code=202)
async def execute_capability(
    capability_id: str,
    request: CapabilityExecutionRequest,
    user=Depends(get_current_user),
):
    try:
        capability = get_capability(capability_id)
        options = validate_capability_options(capability, request.options)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user_id = str(user.get('user_id'))
    asset = await _asset_for_execution(request.asset_id, request.project_id, user_id)
    if asset is None:
        raise HTTPException(status_code=404, detail='Asset not found or inaccessible')
    if asset.type not in capability.asset_types:
        raise HTTPException(
            status_code=409,
            detail=f'Capability {capability.id} does not support asset type {asset.type}',
        )

    target = asset_target(asset)
    if not target:
        raise HTTPException(status_code=409, detail='Asset has no executable target')

    config = {
        'target': target,
        **options,
        'capability_id': capability.id,
        'capability_category': capability.category,
        'capability_risk': capability.risk,
        'capability_policy_version': _POLICY_VERSION,
        'capability_source': capability.source,
    }
    scan_request = ScanCreate(
        project_id=request.project_id,
        asset_id=request.asset_id,
        name=f'{capability.id} validation for {asset.name}',
        scan_type=capability.scan_type,
        engines=[capability.tool],
        depth=request.depth,
        config=config,
    )
    created, engines = await _create_scan(scan_request, user_id)
    task = _TASKS[engines[0]].delay(str(created.id))
    created = await _attach_celery_task(str(created.id), task.id)
    serialized = await _serialize_scan(created)
    return {
        'capability_id': capability.id,
        'policy_version': _POLICY_VERSION,
        'authorization_required': capability.authorization_required,
        'evidence_required': capability.evidence_required,
        'execution_mode': capability.execution_mode,
        'scan': serialized,
    }
