from datetime import timezone
from typing import List, Optional
import os

from asgiref.sync import sync_to_async
from django.db import transaction
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from ..core.dependencies import get_current_user
from ..services.authorization_guard import asset_target
from ..services.scope_authorization import ScopeAuthorizationError, require_authorized_target
from ..tasks.advanced_scans import run_masscan_scan, run_semgrep_scan
from ..tasks.security_scan import run_nmap_scan, run_nuclei_scan

router = APIRouter()
SUPPORTED_ENGINES = {'nmap', 'nuclei', 'masscan', 'semgrep'}
NETWORK_SCAN_TYPES = {'ip', 'url', 'network'}


class ScanCreate(BaseModel):
    project_id: str
    name: str
    scan_type: str
    asset_id: Optional[str] = None
    engines: List[str] = Field(default_factory=lambda: ['nmap'])
    depth: str = 'standard'
    config: dict = Field(default_factory=dict)
    # Compatibility-only input. It is deliberately ignored for authority.
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
        id=str(scan.id), project_id=str(scan.project_id), name=scan.name,
        scan_type=scan.scan_type, status=scan.status, progress=round(scan.progress),
        current_phase=scan.current_phase, security_score=scan.security_score,
        risk_level=scan.risk_level or 'unknown', findings_count=scan.findings_count,
        created_at=scan.created_at.astimezone(timezone.utc).isoformat(),
        started_at=scan.started_at.astimezone(timezone.utc).isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.astimezone(timezone.utc).isoformat() if scan.completed_at else None,
    )


@sync_to_async
def _list_scans(user_id: str, project_id: Optional[str], status: Optional[str], limit: int, offset: int):
    qs = (Scan.objects.select_related('project').filter(project__members=user_id)
          | Scan.objects.select_related('project').filter(project__owner_id=user_id)).distinct().order_by('-created_at')
    if project_id:
        qs = qs.filter(project_id=project_id)
    if status:
        qs = qs.filter(status=status)
    return list(qs[offset:offset + limit])


def _request_target(scan: ScanCreate) -> Optional[str]:
    for key in ('target', 'host', 'ip', 'url', 'domain', 'cidr'):
        value = scan.config.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _bind_network_authorization(scan: ScanCreate, asset: Asset, requested_target: Optional[str]) -> tuple[Asset, str, AssetAuthorization]:
    current_target = asset_target(asset)
    if not current_target:
        raise HTTPException(status_code=400, detail='Authorized asset has no executable target')
    if requested_target and requested_target != current_target:
        raise HTTPException(status_code=409, detail='Scan target must exactly match the authorized asset target')
    latest = (AssetAuthorization.objects.select_for_update().filter(asset=asset)
              .order_by('-created_at', '-id').first())
    if latest is None or latest.authorized is not True or not latest.is_currently_valid:
        raise HTTPException(status_code=403, detail='The asset has no currently valid authoritative authorization decision')
    if latest.asset_identity_snapshot != asset.id:
        raise HTTPException(status_code=403, detail='The authorization decision is not bound to the current asset identity')
    if latest.target_snapshot != current_target:
        raise HTTPException(status_code=409, detail='The authorized asset target no longer matches the authoritative authorization snapshot')
    try:
        require_authorized_target(current_target, url=scan.scan_type == 'url')
    except ScopeAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return asset, current_target, latest


@router.get('/', response_model=List[ScanResponse])
async def list_scans(project_id: Optional[str] = None, status: Optional[str] = None,
                     limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
                     user=Depends(get_current_user)):
    return [await _serialize_scan(s) for s in await _list_scans(str(user.get('user_id')), project_id, status, limit, offset)]


@sync_to_async
def _create_scan(scan: ScanCreate, user_id: str):
    with transaction.atomic():
        project = (Project.objects.select_for_update().filter(id=scan.project_id, owner_id=user_id).first()
                   or Project.objects.select_for_update().filter(id=scan.project_id, members=user_id).first())
        if not project:
            raise HTTPException(status_code=404, detail='Project not found or access denied')
        engines = [e.strip().lower() for e in scan.engines if e.strip()] or ['nmap']
        if len(set(engines)) != len(engines):
            raise HTTPException(status_code=400, detail='Duplicate scanner engines are not allowed')
        if any(e not in SUPPORTED_ENGINES for e in engines):
            raise HTTPException(status_code=400, detail=f'Unsupported scanner engine. Allowed: {sorted(SUPPORTED_ENGINES)}')
        if len(engines) > 1:
            raise HTTPException(status_code=400, detail='A Scan currently executes exactly one real engine; create one Scan per engine to preserve execution isolation.')

        asset = None
        if scan.asset_id:
            asset = Asset.objects.select_for_update().filter(id=scan.asset_id, project=project).first()
            if not asset:
                raise HTTPException(status_code=404, detail='Asset not found')

        requested_target = _request_target(scan)
        authorization = None
        if scan.scan_type in NETWORK_SCAN_TYPES:
            if asset is None:
                raise HTTPException(status_code=400, detail='Network scans require an existing asset with an authoritative authorization decision')
            asset, target, authorization = _bind_network_authorization(scan, asset, requested_target)
        else:
            target = requested_target

        if engines[0] == 'nuclei':
            if not asset or not asset_target(asset) or asset.type not in {Asset.Type.WEBSITE, Asset.Type.API_ENDPOINT}:
                raise HTTPException(status_code=400, detail='Nuclei scans require a website/API asset with a URL target')
        if engines[0] == 'semgrep' and (not asset or not ((asset.configuration or {}).get('repo_url') or (asset.configuration or {}).get('path'))):
            raise HTTPException(status_code=400, detail='Semgrep scans require asset configuration.repo_url or configuration.path')

        obj = Scan.objects.create(
            project=project, name=scan.name, scan_type=scan.scan_type, asset=asset,
            authorization_decision=authorization, engines=engines, depth=scan.depth,
            config=scan.config, initiated_by_id=user_id, status=Scan.Status.QUEUED,
        )
        return obj, engines


@sync_to_async
def _attach_celery_task(scan_id: str, task_id: str):
    scan = Scan.objects.get(pk=scan_id)
    scan.celery_task_id = task_id
    scan.save(update_fields=['celery_task_id', 'updated_at'])
    return scan


@router.post('/', response_model=ScanResponse, status_code=201)
async def create_scan(scan: ScanCreate, user=Depends(get_current_user)):
    created, engines = await _create_scan(scan, str(user.get('user_id')))
    task_map = {'nmap': run_nmap_scan, 'nuclei': run_nuclei_scan, 'masscan': run_masscan_scan, 'semgrep': run_semgrep_scan}
    result = task_map[engines[0]].delay(str(created.id))
    created = await _attach_celery_task(str(created.id), result.id)
    return await _serialize_scan(created)


@sync_to_async
def _get_scan(scan_id: str, user_id: str):
    return (Scan.objects.select_related('project').filter(id=scan_id, project__members=user_id).first()
            or Scan.objects.select_related('project').filter(id=scan_id, project__owner_id=user_id).first())


@router.get('/{scan_id}', response_model=ScanResponse)
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan(scan_id, str(user.get('user_id')))
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    return await _serialize_scan(scan)


@sync_to_async
def _delete_scan(scan_id: str, user_id: str):
    scan = (Scan.objects.filter(id=scan_id, project__members=user_id).first()
            or Scan.objects.filter(id=scan_id, project__owner_id=user_id).first())
    if not scan:
        return False
    scan.delete()
    return True


@router.delete('/{scan_id}')
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    if not await _delete_scan(scan_id, str(user.get('user_id'))):
        raise HTTPException(status_code=404, detail='Scan not found')
    return {'message': 'Scan deleted'}


@sync_to_async
def _logs(scan_id: str, user_id: str, limit: int):
    scan = (Scan.objects.filter(id=scan_id, project__members=user_id).first()
            or Scan.objects.filter(id=scan_id, project__owner_id=user_id).first())
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
    scan = (Scan.objects.filter(id=scan_id, project__members=user_id).first()
            or Scan.objects.filter(id=scan_id, project__owner_id=user_id).first())
    if not scan:
        return None
    return [
        {'id': str(x.id), 'engine': x.engine.name, 'status': x.status, 'progress': x.progress,
         'findings_found': x.findings_found, 'evidences_collected': x.evidences_collected,
         'result_data': x.result_data, 'error_message': x.error_message}
        for x in scan.engine_executions.select_related('engine').all()
    ]


@router.get('/{scan_id}/engine-executions')
async def get_engine_executions(scan_id: str, user=Depends(get_current_user)):
    result = await _executions(scan_id, str(user.get('user_id')))
    if result is None:
        raise HTTPException(status_code=404, detail='Scan not found')
    return result
