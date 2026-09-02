from __future__ import annotations

from datetime import timezone
from typing import List

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.dependencies import get_current_user
from assets.models import Asset, AssetRelationship
from projects.models import Project
from vulnerabilities.models import Vulnerability

router = APIRouter()


class TwinResponse(BaseModel):
    id: str
    project_id: str
    name: str
    status: str
    environment: dict
    created_at: str
    source: str


class ScenarioCreate(BaseModel):
    name: str
    change_type: str
    description: str = ''
    affected_nodes: List[str] = Field(default_factory=list)
    parameters: dict = Field(default_factory=dict)


class ScenarioResponse(BaseModel):
    id: str
    twin_id: str
    name: str
    change_type: str
    description: str
    affected_nodes: List[str]
    security_impact: float
    performance_impact: float
    risk_reduction: float
    recommendation: str
    status: str
    created_at: str
    source: str


@sync_to_async
def _project(project_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project


@sync_to_async
def _graph(project_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    assets = list(Asset.objects.filter(project=project, is_active=True).order_by('name'))
    findings = list(Vulnerability.objects.filter(project=project).select_related('asset').order_by('-risk_score', '-created_at'))
    relationships = list(AssetRelationship.objects.filter(project=project).select_related('source', 'target'))
    nodes = [{'id': f'asset:{asset.id}', 'type': 'asset', 'label': asset.name, 'criticality': asset.criticality, 'environment': asset.environment, 'status': 'active'} for asset in assets]
    nodes.extend({'id': f'finding:{finding.id}', 'type': 'finding', 'label': finding.title, 'severity': finding.severity, 'status': finding.status, 'risk_score': finding.risk_score, 'asset_id': str(finding.asset_id) if finding.asset_id else None} for finding in findings)
    edges = [{'source': f'asset:{rel.source_id}', 'target': f'asset:{rel.target_id}', 'type': rel.relationship_type, 'metadata': rel.metadata} for rel in relationships]
    edges.extend({'source': f'asset:{finding.asset_id}', 'target': f'finding:{finding.id}', 'type': 'has_finding', 'metadata': {'source_engine': finding.source_engine}} for finding in findings if finding.asset_id)
    return {'nodes': nodes, 'edges': edges, 'finding_count': len(findings), 'asset_count': len(assets)}


@router.get('/projects/{project_id}/twins', response_model=List[TwinResponse])
async def list_twins(project_id: str, current_user=Depends(get_current_user)):
    project = await _project(project_id, str(current_user.get('user_id')))
    return [TwinResponse(id=f'live:{project.id}', project_id=str(project.id), name=f'{project.name} live security twin', status='live', environment={'project_environment': project.environment}, created_at=project.created_at.astimezone(timezone.utc).isoformat(), source='postgresql')]


@router.post('/projects/{project_id}/twins', response_model=TwinResponse)
async def create_twin(project_id: str, name: str, current_user=Depends(get_current_user)):
    project = await _project(project_id, str(current_user.get('user_id')))
    return TwinResponse(id=f'live:{project.id}', project_id=str(project.id), name=name, status='live', environment={'project_environment': project.environment}, created_at=project.created_at.astimezone(timezone.utc).isoformat(), source='postgresql')


@router.get('/twins/{twin_id}', response_model=TwinResponse)
async def get_twin(twin_id: str, current_user=Depends(get_current_user)):
    if not twin_id.startswith('live:'):
        raise HTTPException(status_code=404, detail='Only database-derived live twins are supported')
    project = await _project(twin_id.split(':', 1)[1], str(current_user.get('user_id')))
    return TwinResponse(id=f'live:{project.id}', project_id=str(project.id), name=f'{project.name} live security twin', status='live', environment={'project_environment': project.environment}, created_at=project.created_at.astimezone(timezone.utc).isoformat(), source='postgresql')


@router.post('/twins/{twin_id}/build')
async def build_twin(twin_id: str, current_user=Depends(get_current_user)):
    if not twin_id.startswith('live:'):
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    return {'status': 'completed', 'source': 'postgresql', 'graph': await _graph(twin_id.split(':', 1)[1], str(current_user.get('user_id')))}


@router.get('/twins/{twin_id}/scenarios', response_model=List[ScenarioResponse])
async def list_scenarios(twin_id: str, current_user=Depends(get_current_user)):
    if not twin_id.startswith('live:'):
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    await _project(twin_id.split(':', 1)[1], str(current_user.get('user_id')))
    return []


@router.post('/twins/{twin_id}/scenarios', response_model=ScenarioResponse)
async def create_scenario(twin_id: str, scenario: ScenarioCreate, current_user=Depends(get_current_user)):
    if not twin_id.startswith('live:'):
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    project = await _project(twin_id.split(':', 1)[1], str(current_user.get('user_id')))
    if scenario.change_type not in {'close_finding', 'disable_asset'}:
        raise HTTPException(status_code=400, detail='Only database-observable scenario types are supported: close_finding or disable_asset')
    graph = await _graph(str(project.id), str(current_user.get('user_id')))
    affected = set(scenario.affected_nodes)
    affected_findings = [node for node in graph['nodes'] if node['type'] == 'finding' and node['id'] in affected]
    risk_reduction = round(sum(float(node.get('risk_score') or 0) for node in affected_findings), 2)
    return ScenarioResponse(id=f'analysis:{project.id}:{scenario.name}', twin_id=twin_id, name=scenario.name, change_type=scenario.change_type, description=scenario.description, affected_nodes=list(affected), security_impact=-risk_reduction, performance_impact=0.0, risk_reduction=risk_reduction, recommendation='Apply the change only after validating affected findings and authorization scope.', status='analyzed', created_at=project.created_at.astimezone(timezone.utc).isoformat(), source='postgresql')


@router.post('/scenarios/{scenario_id}/simulate', response_model=ScenarioResponse)
async def simulate_scenario(scenario_id: str, current_user=Depends(get_current_user)):
    raise HTTPException(status_code=409, detail='Predictive simulation is disabled until a persisted scenario model and validated simulation engine are available')


@router.post('/twins/{twin_id}/drift-check')
async def check_drift(twin_id: str, current_assets: List[dict], current_user=Depends(get_current_user)):
    if not twin_id.startswith('live:'):
        raise HTTPException(status_code=404, detail='Digital Twin not found')
    graph = await _graph(twin_id.split(':', 1)[1], str(current_user.get('user_id')))
    model_ids = {node['id'] for node in graph['nodes'] if node['type'] == 'asset'}
    supplied_ids = {value if value.startswith('asset:') else f'asset:{value}' for value in (str(item.get('id')) for item in current_assets if item.get('id'))}
    return {'drift': len(model_ids.symmetric_difference(supplied_ids)), 'missing_in_model': sorted(supplied_ids - model_ids), 'extra_in_model': sorted(model_ids - supplied_ids), 'status': 'completed', 'source': 'postgresql'}
