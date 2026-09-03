from datetime import datetime, timezone
from typing import List, Optional

import os

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution, ScanLog

from ..core.dependencies import get_current_user
from ..tasks.security_scan import run_nmap_scan

router = APIRouter()
NETWORK_SCAN_TYPES = {'ip', 'url', 'network'}


class ScanCreate(BaseModel):
    project_id: str
    name: str
    scan_type: str
    asset_id: Optional[str] = None
    engines: List[str] = Field(default_factory=list)
    depth: str = 'standard'
    config: dict = Field(default_factory=dict)
    # Backwards-compatible request field only. It MUST NOT grant authorization.
    authorized: bool = False


class ScanResponse(BaseModel):
    id: str
    project_id: str
    name: str
    scan_type: str
    status: str
    progress: int
    current_phase: str
    security_score: float
    risk_level: str
    findings_count: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@sync_to_async
def _serialize_scan(scan: Scan):
    return ScanResponse(
        id=str(scan.id), project_id=str(scan.project_id), name=scan.name, scan_type=scan.scan_type,
        status=scan.status, progress=round(scan.progress), current_phase=scan.current_phase,
        security_score=scan.security_score, risk_level=scan.risk_level or 'unknown',
        findings_count=scan.findings_count, created_at=scan.created_at.astimezone(timezone.utc).isoformat(),
        started_at=scan.started_at.astimezone(timezone.utc).isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.astimezone(timezone.utc).isoformat() if scan.completed_at else None,
    )


@sync_to_async
def _list_scans(user_id: str, project_id: Optional[str], status: Optional[str], limit: int, offset: int):
    qs = Scan.objects.select_related('project').filter(project__members=user_id) | Scan.objects.select_related('project').filter(project__owner_id=user_id)
    qs = qs.distinct().order_by('-created_at')
    if project_id:
        qs = qs.filter(project_id=project_id)
    if status:
        qs = qs.filter(status=status)
    return list(qs[offset:offset + limit])


@router.get('/', response_model=List[ScanResponse])
async def list_scans(project_id: Optional[str] = None, status: Optional[str] = None, limit: int = Query(20, le=100), offset: int = 0, user=Depends(get_current_user)):
    return [await _serialize_scan(scan) for scan in await _list_scans(str(user.get('user_id')), project_id, status, limit, offset)]


@sync_to_async
def _create_scan(scan: ScanCreate, user_id: str):
    project = Project.objects.filter(id=scan.project_id).filter(members=user_id).first() or Project.objects.filter(id=scan.project_id, owner_id=user_id).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or access denied')
    asset = None
    if scan.asset_id:
        asset = Asset.objects.filter(id=scan.asset_id, project=project).first()
        if not asset:
            raise HTTPException(status_code=404, detail='Asset not found')

    # Network execution has a strict server-side authorization boundary.
    # The client `authorized` field is intentionally ignored as an authority.
    # The latest persisted authorization decision is the security source of truth.
    if scan.scan_type in NETWORK_SCAN_TYPES:
        if not asset:
            raise HTTPException(
                status_code=400,
                detail='A real network scan requires an existing project asset; authorization must be established on the asset before execution',
            )
        if not asset.is_active:
            raise HTTPException(status_code=403, detail='The selected asset is inactive and cannot be used for network execution')

        from django_project.assets.models import AssetAuthorization

        authorization = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at').first()
        if not authorization or authorization.authorized is not True:
            raise HTTPException(status_code=403, detail='The selected asset does not have an active persisted network authorization decision')

        requested_target = scan.config.get('target') or scan.config.get('host') or scan.config.get('ip') or scan.config.get('url')
        persisted_target = authorization.target_snapshot or ''
        if requested_target:
            normalized_requested = str(requested_target).strip()
            if persisted_target != normalized_requested:
                raise HTTPException(status_code=409, detail='Requested scan target does not match the authorized asset identity')

    obj = Scan.objects.create(project=project, name=scan.name, scan_type=scan.scan_type, asset=asset, engines=scan.engines or ['nmap'], depth=scan.depth, config=scan.config, initiated_by_id=user_id)
    return obj


@router.post('/', response_model=ScanResponse, status_code=201)
async def create_scan(scan: ScanCreate, user=Depends(get_current_user)):
    return await _serialize_scan(await _create_scan(scan, str(user.get('user_id'))))


@sync_to_async
def _get_scan(scan_id: str, user_id: str):
    return (Scan.objects.select_related('project').filter(id=scan_id).filter(project__members=user_id).first() or Scan.objects.select_related('project').filter(id=scan_id, project__owner_id=user_id).first())


@router.get('/{scan_id}', response_model=ScanResponse)
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan(scan_id, str(user.get('user_id')))
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    return await _serialize_scan(scan)


@sync_to_async
def _delete_scan(scan_id: str, user_id: str):
    scan = _get_scan_sync(scan_id, user_id)
    if not scan:
        return False
    scan.delete()
    return True


def _get_scan_sync(scan_id: str, user_id: str):
    return (Scan.objects.filter(id=scan_id, project__members=user_id).first() or Scan.objects.filter(id=scan_id, project__owner_id=user_id).first())


@router.delete('/{scan_id}')
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    if not await _delete_scan(scan_id, str(user.get('user_id'))):
        raise HTTPException(status_code=404, detail='Scan not found')
    return {'message': 'Scan deleted'}


@sync_to_async
def _logs(scan_id: str, user_id: str, limit: int):
    scan = _get_scan_sync(scan_id, user_id)
    if not scan:
        return None
    return [{'id': str(x.id), 'level': x.level, 'message': x.message, 'context': x.context, 'created_at': x.created_at.isoformat()} for x in scan.logs.all()[:limit]]


@router.get('/{scan_id}/logs')
async def get_scan_logs(scan_id: str, limit: int = 100, user=Depends(get_current_user)):
    result = await _logs(scan_id, str(user.get('user_id')), min(limit, 500))
    if result is None:
        raise HTTPException(status_code=404, detail='Scan not found')
    return result


@sync_to_async
def _executions(scan_id: str, user_id: str):
    scan = _get_scan_sync(scan_id, user_id)
    if not scan:
        return None
    return [{'id': str(x.id), 'engine': x.engine.name, 'status': x.status, 'progress': x.progress, 'findings_found': x.findings_found, 'evidences_collected': x.evidences_collected, 'result_data': x.result_data, 'error_message': x.error_message} for x in scan.engine_executions.select_related('engine').all()]


@router.get('/{scan_id}/engine-executions')
async def get_engine_executions(scan_id: str, user=Depends(get_current_user)):
    result = await _executions(scan_id, str(user.get('user_id')))
    if result is None:
        raise HTTPException(status_code=404, detail='Scan not found')
    return result
