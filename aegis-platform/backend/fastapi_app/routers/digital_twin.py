from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List
from uuid import UUID

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

    nodes = []
    for asset in assets:
        nodes.append({
            'id': str(asset.id),
            'type': 'asset',
            'name': asset.name,
            'asset_type': asset.type,
            'environment': asset.environment,
            'criticality': asset.criticality,
            'active': asset.is_active,
        })

    edges = [
        {
            'source': str(rel.source_id),
            'target': str(rel.target_id),
            'relationship': rel.relationship_type,
            'metadata': rel.metadata or {},
        }
        for rel in relationships
    ]
    open_findings = [f for f in findings if getattr(f, 'status', None) not in {'fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'}]
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'source': 'postgresql',
        'nodes': nodes,
        'edges': edges,
        'finding_count': len(findings),
        'open_finding_count': len(open_findings),
        'assets': {'total': len(assets)},
    }


@sync_to_async
def _list_twins(project_id: str) -> list[DigitalTwin]:
    return list(DigitalTwin.objects.filter(project_id=project_id).order_by('-updated_at'))


@sync_to_async
def _create_twin(project_id: str, name: str, asset_ids: list[str], user_id: str) -> DigitalTwin:
    twin = DigitalTwin.objects.create(project_id=project_id, name=name, created_by_id=user_id, status=DigitalTwin.Status.BUILDING)
    allowed_assets = {str(v) for v in Asset.objects.filter(project_id=project_id, is_active=True, id__in=asset_ids).values_list('id', flat=True)} if asset_ids else {
        str(v) for v in Asset.objects.filter(project_id=project_id, is_active=True).values_list('id', flat=True)
    }
    for asset in Asset.objects.filter(project_id=project_id, is_active=True, id__in=allowed_assets):
        DigitalTwinNode.objects.create(
            twin=twin,
            asset=asset,
            node_type='asset',
            snapshot={
                'name': asset.name,
                'type': asset.type,
                'environment': asset.environment,
                'criticality': asset.criticality,
                'configuration': asset.configuration or {},
                'tags': asset.tags or [],
            },
        )
    return twin


@sync_to_async
def _build_twin(twin_id: str) -> DigitalTwin:
    twin = DigitalTwin.objects.select_related('project').get(pk=twin_id)
    environment = _build_environment_sync(str(twin.project_id))
    twin.environment = environment
    twin.status = DigitalTwin.Status.READY
    twin.built_at = datetime.now(timezone.utc)
    twin.save(update_fields=['environment', 'status', 'built_at', 'updated_at'])
    return twin


def _build_environment_sync(project_id: str) -> dict[str, Any]:
    assets = list(Asset.objects.filter(project_id=project_id, is_active=True).order_by('id'))
    relationships = list(AssetRelationship.objects.filter(project_id=project_id).select_related('source', 'target').order_by('id'))
    findings = list(Vulnerability.objects.filter(project_id=project_id).order_by('id'))
    nodes = [{'id': str(a.id), 'type': 'asset', 'name': a.name, 'asset_type': a.type, 'environment': a.environment, 'criticality': a.criticality, 'active': a.is_active} for a in assets]
    edges = [{'source': str(r.source_id), 'target': str(r.target_id), 'relationship': r.relationship_type, 'metadata': r.metadata or {}} for r in relationships]
    closed = {'fixed', 'false_positive', 'accepted_risk', 'wont_fix', 'duplicate'}
    open_count = sum(1 for f in findings if str(f.status) not in closed)
    return {'generated_at': datetime.now(timezone.utc).isoformat(), 'source': 'postgresql', 'nodes': nodes, 'edges': edges, 'finding_count': len(findings), 'open_finding_count': open_count, 'assets': {'total': len(assets)}}


@sync_to_async
def _get_twin(twin_id: str) -> DigitalTwin:
    return DigitalTwin.objects.get(pk=twin_id)


@sync_to_async
def _scenarios(twin_id: str) -> list[TwinScenario]:
    return list(TwinScenario.objects.filter(twin_id=twin_id).order_by('-created_at'))


@sync_to_async
def _create_scenario(twin_id: str, body: ScenarioCreate, user_id: str) -> TwinScenario:
    twin = DigitalTwin.objects.get(pk=twin_id)
    nodes = list(DigitalTwinNode.objects.filter(twin=twin).select_related('asset'))
    available = {str(node.asset_id): node for node in nodes}
    requested = [str(v) for v in body.affected_nodes]
    selected = requested or list(available)
    unknown = [v for v in selected if v not in available]
    if unknown:
        raise ValueError('Affected nodes must reference assets already persisted in this Digital Twin')
    affected = [available[v] for v in selected]
    findings = Vulnerability.objects.filter(asset_id__in=[node.asset_id for node in affected])
    severity_weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    risk = sum(severity_weight.get(str(f.severity).lower(), 0) for f in findings)
    return TwinScenario.objects.create(
        twin=twin,
        name=body.name,
        change_type=body.change_type,
        description=body.description,
        parameters=body.parameters,
        affected_nodes=selected,
        security_impact=float(risk),
        performance_impact=None,
        risk_reduction=None,
        recommendation='Scenario is persisted against real twin nodes. Simulation requires a supported, deterministic control model.',
        status=TwinScenario.Status.PENDING,
        created_by_id=user_id,
    )


@sync_to_async
def _drift(twin_id: str, project_id: str) -> dict[str, Any]:
    twin_ids = {str(v) for v in DigitalTwinNode.objects.filter(twin_id=twin_id).values_list('asset_id', flat=True)}
    current_ids = {str(v) for v in Asset.objects.filter(project_id=project_id, is_active=True).values_list('id', flat=True)}
    missing = sorted(twin_ids - current_ids)
    extra = sorted(current_ids - twin_ids)
    drift = len(missing) + len(extra)
    twin = DigitalTwin.objects.get(pk=twin_id)
    twin.status = DigitalTwin.Status.DRIFTED if drift else DigitalTwin.Status.READY
    twin.save(update_fields=['status', 'updated_at'])
    return {'drift': drift, 'missing_in_model': missing, 'extra_in_model': extra, 'status': 'drifted' if drift else 'ready'}


@router.get('/projects/{project_id}/twins', response_model=List[TwinResponse])
async def list_twins(project_id: str, current_user=Depends(get_current_user)):
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(project_id, user_id):
        raise HTTPException(status_code=403, detail='Project access denied')
    twins = await _list_twins(project_id)
    return [TwinResponse(id=str(t.id), project_id=str(t.project_id), name=t.name, status=t.status, environment=t.environment or {}, created_at=t.created_at.isoformat(), updated_at=t.updated_at.isoformat(), built_at=t.built_at.isoformat() if t.built_at else None) for t in twins]


@router.post('/projects/{project_id}/twins', response_model=TwinResponse)
async def create_twin(project_id: str, name: str, assets: List[str] = Query(default=[]), current_user=Depends(get_current_user)):
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(project_id, user_id):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        twin = await _create_twin(project_id, name, assets, user_id)
        twin = await _build_twin(str(twin.id))
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Project or Digital Twin not found')
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return TwinResponse(id=str(twin.id), project_id=str(twin.project_id), name=twin.name, status=twin.status, environment=twin.environment or {}, created_at=twin.created_at.isoformat(), updated_at=twin.updated_at.isoformat(), built_at=twin.built_at.isoformat() if twin.built_at else None)


@router.get('/twins/{twin_id}', response_model=TwinResponse)
async def get_twin(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(str(twin.project_id), user_id):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return TwinResponse(id=str(twin.id), project_id=str(twin.project_id), name=twin.name, status=twin.status, environment=twin.environment or {}, created_at=twin.created_at.isoformat(), updated_at=twin.updated_at.isoformat(), built_at=twin.built_at.isoformat() if twin.built_at else None)


@router.post('/twins/{twin_id}/build', response_model=TwinResponse)
async def build_twin(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(str(twin.project_id), user_id):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    try:
        twin = await _build_twin(twin_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return TwinResponse(id=str(twin.id), project_id=str(twin.project_id), name=twin.name, status=twin.status, environment=twin.environment or {}, created_at=twin.created_at.isoformat(), updated_at=twin.updated_at.isoformat(), built_at=twin.built_at.isoformat() if twin.built_at else None)


@router.get('/twins/{twin_id}/scenarios', response_model=List[ScenarioResponse])
async def list_scenarios(twin_id: str, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(str(twin.project_id), user_id):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    scenarios = await _scenarios(twin_id)
    return [ScenarioResponse(id=str(s.id), twin_id=str(s.twin_id), name=s.name, change_type=s.change_type, description=s.description, affected_nodes=s.affected_nodes or [], security_impact=s.security_impact, performance_impact=s.performance_impact, risk_reduction=s.risk_reduction, recommendation=s.recommendation, status=s.status, created_at=s.created_at.isoformat(), updated_at=s.updated_at.isoformat()) for s in scenarios]


@router.post('/twins/{twin_id}/scenarios', response_model=ScenarioResponse)
async def create_scenario(twin_id: str, scenario: ScenarioCreate, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(str(twin.project_id), user_id):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    try:
        created = await _create_scenario(twin_id, scenario, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return ScenarioResponse(id=str(created.id), twin_id=str(created.twin_id), name=created.name, change_type=created.change_type, description=created.description, affected_nodes=created.affected_nodes or [], security_impact=created.security_impact, performance_impact=created.performance_impact, risk_reduction=created.risk_reduction, recommendation=created.recommendation, status=created.status, created_at=created.created_at.isoformat(), updated_at=created.updated_at.isoformat())


@router.post('/scenarios/{scenario_id}/simulate', response_model=ScenarioResponse)
async def simulate_scenario(scenario_id: str, request: SimulationRequest, current_user=Depends(get_current_user)):
    raise HTTPException(status_code=501, detail='Scenario simulation is not implemented without a deterministic control-effect model; no synthetic result will be returned')


@router.post('/twins/{twin_id}/drift-check')
async def check_drift(twin_id: str, current_assets: List[str] | None = None, current_user=Depends(get_current_user)):
    try:
        twin = await _get_twin(twin_id)
    except DigitalTwin.DoesNotExist:
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    user_id = str(current_user.get('user_id') or current_user.get('id'))
    if not await _project_access(str(twin.project_id), user_id):
        raise HTTPException(status_code=403, detail='Digital Twin access denied')
    return await _drift(twin_id, str(twin.project_id))
