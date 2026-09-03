from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from django_project.assets.models import Asset, AssetRelationship
from django_project.digital_twin.models import DigitalTwin, DigitalTwinNode, TwinScenario
from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability

from ..core.dependencies import get_current_user

router = APIRouter()


class TwinResponse(BaseModel):
    id: str
    project_id: str
    name: str
    status: str
    environment: dict[str, Any]
    created_at: str
    updated_at: str
    built_at: str | None


class ScenarioCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    change_type: str = Field(min_length=1, max_length=50)
    description: str = ''
    affected_nodes: List[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScenarioResponse(BaseModel):
    id: str
    twin_id: str
    name: str
    change_type: str
    description: str
    affected_nodes: List[str]
    security_impact: float | None
    performance_impact: float | None
    risk_reduction: float | None
    recommendation: str
    status: str
    created_at: str
    updated_at: str


class SimulationRequest(BaseModel):
    scenario_id: str


@sync_to_async
def _project_access(project_id: str, user_id: str) -> bool:
    project = Project.objects.filter(pk=project_id).first()
    return bool(project and (str(project.owner_id) == str(user_id) or project.members.filter(pk=user_id).exists()))


@sync_to_async
def _build_environment(project_id: str) -> dict[str, Any]:
    assets = list(Asset.objects.filter(project_id=project_id, is_active=True).order_by('id'))
    relationships = list(AssetRelationship.objects.filter(project_id=project_id).select_related('source', 'target').order_by('id'))
    findings = list(Vulnerability.objects.filter(project_id=project_id).order_by('id'))
    nodes = [{'id': str(asset.id), 'type': 'asset', 'name': asset.name, 'asset_type': asset.type, 'environment': asset.environment, 'criticality': asset.criticality, 'active': asset.is_active} for asset in assets]
    edges = [{'source': str(rel.source_id), 'target': str(rel.target_id), 'relationship': rel.relationship_type, 'metadata': rel.metadata or {}} for rel in relationships]
    closed = {'fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'}
    return {'generated_at': datetime.now(timezone.utc).isoformat(), 'source': 'postgresql', 'nodes': nodes, 'edges': edges, 'finding_count': len(findings), 'open_finding_count': sum(1 for f in findings if str(f.status) not in closed), 'assets': {'total': len(assets)}}


@sync_to_async
def _list_twins(project_id: str) -> list[DigitalTwin]:
    return list(DigitalTwin.objects.filter(project_id=project_id).order_by('-updated_at'))


@sync_to_async
def _create_twin(project_id: str, name: str, asset_ids: list[str], user_id: str) -> DigitalTwin:
    twin = DigitalTwin.objects.create(project_id=project_id, name=name, created_by_id=user_id, status=DigitalTwin.Status.BUILDING)
    available = Asset.objects.filter(project_id=project_id, is_active=True)
    if asset_ids:
        selected = {str(v) for v in available.filter(id__in=asset_ids).values_list('id', flat=True)}
    else:
        selected = {str(v) for v in available.values_list('id', flat=True)}
    for asset in available.filter(id__in=selected):
        DigitalTwinNode.objects.create(twin=twin, asset=asset, node_type='asset', snapshot={'name': asset.name, 'type': asset.type, 'environment': asset.environment, 'criticality': asset.criticality, 'configuration': asset.configuration or {}, 'tags': asset.tags or []})
    return twin


def _build_environment_sync(project_id: str) -> dict[str, Any]:
    assets = list(Asset.objects.filter(project_id=project_id, is_active=True).order_by('id'))
    relationships = list(AssetRelationship.objects.filter(project_id=project_id).select_related('source', 'target').order_by('id'))
    findings = list(Vulnerability.objects.filter(project_id=project_id).order_by('id'))
    closed = {'fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'}
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source': 'postgresql',
        'nodes': [{'id': str(a.id), 'type': 'asset', 'name': a.name, 'asset_type': a.type, 'environment': a.environment, 'criticality': a.criticality, 'active': a.is_active} for a in assets],
        'edges': [{'source': str(r.source_id), 'target': str(r.target_id), 'relationship': r.relationship_type, 'metadata': r.metadata or {}} for r in relationships],
        'finding_count': len(findings),
        'open_finding_count': sum(1 for f in findings if str(f.status) not in closed),
        'assets': {'total': len(assets)},
    }


@sync_to_async
def _build_twin(twin_id: str) -> DigitalTwin:
    twin = DigitalTwin.objects.get(pk=twin_id)
    twin.environment = _build_environment_sync(str(twin.project_id))
    twin.status = DigitalTwin.Status.READY
    twin.built_at = datetime.now(timezone.utc)
    twin.save(update_fields=['environment', 'status', 'built_at', 'updated_at'])
    return twin


@sync_to_async
def _get_twin(twin_id: str) -> DigitalTwin:
    return DigitalTwin.objects.get(pk=twin_id)


@sync_to_async
def _scenarios(twin_id: str) -> list[TwinScenario]:
    return list(TwinScenario.objects.filter(twin_id=twin_id).order_by('-created_at'))


@sync_to_async
def _create_scenario(twin_id: str, body: ScenarioCreate, user_id: str) -> TwinScenario:
    twin = DigitalTwin.objects.get(pk=twin_id)
    nodes = {str(n.asset_id): n for n in DigitalTwinNode.objects.filter(twin=twin).select_related('asset')}
    selected = [str(v) for v in (body.affected_nodes or list(nodes))]
    unknown = [v for v in selected if v not in nodes]
    if unknown:
        raise ValueError('Affected nodes must reference assets already persisted in this Digital Twin')
    findings = Vulnerability.objects.filter(asset_id__in=[nodes[v].asset_id for v in selected])
    weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    risk = sum(weights.get(str(f.severity).lower(), 0) for f in findings)
    return TwinScenario.objects.create(twin=twin, name=body.name, change_type=body.change_type, description=body.description, parameters=body.parameters, affected_nodes=selected, security_impact=float(risk), performance_impact=None, risk_reduction=None, recommendation='Scenario is persisted against real twin nodes. Simulation requires a supported deterministic control model.', status=TwinScenario.Status.PENDING, created_by_id=user_id)


@sync_to_async
def _drift(twin_id: str, project_id: str) -> dict[str, Any]:
    twin_ids = {str(v) for v in DigitalTwinNode.objects.filter(twin_id=twin_id).values_list('asset_id', flat=True)}
    current_ids = {str(v) for v in Asset.objects.filter(project_id=project_id, is_active=True).values_list('id', flat=True)}
    missing = sorted(twin_ids - current_ids)
    extra = sorted(current_ids - twin_ids)
    twin = DigitalTwin.objects.get(pk=twin_id)
    twin.status = DigitalTwin.Status.DRIFTED if missing or extra else DigitalTwin.Status.READY
    twin.save(update_fields=['status', 'updated_at'])
    return {'drift': len(missing) + len(extra), 'missing_in_model': missing, 'extra_in_model': extra, 'status': 'drifted' if missing or extra else 'ready'}


def _user_id(user: dict[str, Any]) -> str:
    return str(user.get('user_id') or user.get('id'))


def _serialize_twin(twin: DigitalTwin) -> TwinResponse:
    return TwinResponse(id=str(twin.id), project_id=str(twin.project_id), name=twin.name, status=twin.status, environment=twin.environment or {}, created_at=twin.created_at.isoformat(), updated_at=twin.updated_at.isoformat(), built_at=twin.built_at.isoformat() if twin.built_at else None)


def _serialize_scenario(row: TwinScenario) -> ScenarioResponse:
    return ScenarioResponse(id=str(row.id), twin_id=str(row.twin_id), name=row.name, change_type=row.change_type, description=row.description, affected_nodes=row.affected_nodes or [], security_impact=row.security_impact, performance_impact=row.performance_impact, risk_reduction=row.risk_reduction, recommendation=row.recommendation, status=row.status, created_at=row.created_at.isoformat(), updated_at=row.updated_at.isoformat())


@router.get('/projects/{project_id}/twins', response_model=List[TwinResponse])
async def list_twins(project_id: str, current_user=Depends(get_current_user)):
    if not await _project_access(project_id, _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Project access denied')
    return [_serialize_twin(t) for t in await _list_twins(project_id)]


@router.post('/projects/{project_id}/twins', response_model=TwinResponse)
async def create_twin(project_id: str, name: str, assets: List[str] = Query(default=[]), current_user=Depends(get_current_user)):
    if not await _project_access(project_id, _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        return _serialize_twin(await _build_twin(str((await _create_twin(project_id, name, assets, _user_id(current_user))).id)))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get('/twins/{twin_id}', response_model=TwinResponse)
async def get_twin(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    if not await _project_access(str(twin.project_id), _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return _serialize_twin(twin)


@router.post('/twins/{twin_id}/build', response_model=TwinResponse)
async def build_twin(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    if not await _project_access(str(twin.project_id), _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return _serialize_twin(await _build_twin(twin_id))


@router.get('/twins/{twin_id}/scenarios', response_model=List[ScenarioResponse])
async def list_scenarios(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    if not await _project_access(str(twin.project_id), _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return [_serialize_scenario(s) for s in await _scenarios(twin_id)]


@router.post('/twins/{twin_id}/scenarios', response_model=ScenarioResponse)
async def create_scenario(twin_id: str, scenario: ScenarioCreate, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    if not await _project_access(str(twin.project_id), _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    try:
        return _serialize_scenario(await _create_scenario(twin_id, scenario, _user_id(current_user)))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post('/scenarios/{scenario_id}/simulate', response_model=ScenarioResponse)
async def simulate_scenario(scenario_id: str, request: SimulationRequest, current_user=Depends(get_current_user)):
    raise HTTPException(status_code=501, detail='Scenario simulation is not implemented without a deterministic control-effect model; no synthetic result will be returned')


@router.post('/twins/{twin_id}/drift-check')
async def check_drift(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    if not await _project_access(str(twin.project_id), _user_id(current_user)):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return await _drift(twin_id, str(twin.project_id))
