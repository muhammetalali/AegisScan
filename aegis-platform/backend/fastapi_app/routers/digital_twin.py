from __future__ import annotations

from typing import List
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.dependencies import get_current_user
from django_project.projects.models import Project
from enterprise.models import DigitalTwin, TwinNode, TwinScenario
from enterprise.services import ensure_project_tenant
from enterprise.tasks import build_digital_twin_task, predict_digital_twin_scenario_task

router=APIRouter()

class TwinResponse(BaseModel):
    id:str; project_id:str; name:str; status:str; environment:dict; created_at:str; source:str='postgresql'
class ScenarioCreate(BaseModel):
    name:str; change_type:str; description:str=''; affected_nodes:List[str]=Field(default_factory=list); parameters:dict=Field(default_factory=dict)
class ScenarioResponse(BaseModel):
    id:str; twin_id:str; name:str; change_type:str; description:str; affected_nodes:List[str]; security_impact:float; performance_impact:float; risk_reduction:float; recommendation:str; status:str; created_at:str; source:str='postgresql'

@sync_to_async
def _project(project_id:str,user_id:str):
    project=Project.objects.filter(id=project_id).filter(__import__('django').db.models.Q(owner_id=user_id)|__import__('django').db.models.Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404,detail='Project not found or inaccessible')
    return project

@router.get('/projects/{project_id}/twins',response_model=List[TwinResponse])
async def list_twins(project_id:str,user=Depends(get_current_user)):
    await _project(project_id,str(user.get('user_id')))
    rows=await sync_to_async(lambda:list(DigitalTwin.objects.filter(project_id=project_id).values('id','project_id','name','status','snapshot','created_at')))()
    return [TwinResponse(id=str(x['id']),project_id=str(x['project_id']),name=x['name'],status=x['status'],environment=x['snapshot'] or {},created_at=x['created_at'].isoformat()) for x in rows]

@router.post('/projects/{project_id}/twins',response_model=TwinResponse)
async def create_twin(project_id:str,name:str,user=Depends(get_current_user)):
    project=await _project(project_id,str(user.get('user_id'))); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id')))
    twin=await sync_to_async(DigitalTwin.objects.create)(organization=org,project=project,name=name)
    build_digital_twin_task.delay(str(twin.id))
    return TwinResponse(id=str(twin.id),project_id=str(project.id),name=name,status=twin.status,environment={},created_at=twin.created_at.isoformat())

@router.get('/twins/{twin_id}',response_model=TwinResponse)
async def get_twin(twin_id:UUID,user=Depends(get_current_user)):
    twin=await sync_to_async(lambda:DigitalTwin.objects.filter(id=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(id=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    return TwinResponse(id=str(twin.id),project_id=str(twin.project_id),name=twin.name,status=twin.status,environment=twin.snapshot or {},created_at=twin.created_at.isoformat())

@router.post('/twins/{twin_id}/build')
async def build_twin(twin_id:UUID,user=Depends(get_current_user)):
    twin=await sync_to_async(lambda:DigitalTwin.objects.filter(id=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(id=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    task=build_digital_twin_task.delay(str(twin.id)); return {'twin_id':str(twin.id),'task_id':task.id,'status':'queued'}

@router.get('/twins/{twin_id}/scenarios',response_model=List[ScenarioResponse])
async def list_scenarios(twin_id:UUID,user=Depends(get_current_user)):
    twin=await sync_to_async(lambda:DigitalTwin.objects.filter(id=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(id=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    rows=await sync_to_async(lambda:list(TwinScenario.objects.filter(twin=twin).order_by('-created_at')))()
    return [ScenarioResponse(id=str(x.id),twin_id=str(x.twin_id),name=x.name,change_type=x.change_type,description=x.description,affected_nodes=x.affected_nodes,security_impact=float(x.predicted_risk or 0),performance_impact=0,risk_reduction=max(0.0,-float(x.risk_delta or 0)),recommendation=x.recommendation,status=x.status,created_at=x.created_at.isoformat()) for x in rows]

@router.post('/twins/{twin_id}/scenarios',response_model=ScenarioResponse,status_code=201)
async def create_scenario(twin_id:UUID,scenario:ScenarioCreate,user=Depends(get_current_user)):
    twin=await sync_to_async(lambda:DigitalTwin.objects.filter(id=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(id=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    item=await sync_to_async(TwinScenario.objects.create)(twin=twin,name=scenario.name,change_type=scenario.change_type,description=scenario.description,affected_nodes=scenario.affected_nodes,parameters=scenario.parameters,created_by_id=str(user.get('user_id')))
    predict_digital_twin_scenario_task.delay(str(item.id))
    return ScenarioResponse(id=str(item.id),twin_id=str(item.twin_id),name=item.name,change_type=item.change_type,description=item.description,affected_nodes=item.affected_nodes,security_impact=0,performance_impact=0,risk_reduction=0,recommendation='',status=item.status,created_at=item.created_at.isoformat())

@router.post('/scenarios/{scenario_id}/simulate')
async def simulate_scenario(scenario_id:UUID,user=Depends(get_current_user)):
    item=await sync_to_async(lambda:TwinScenario.objects.filter(id=scenario_id,twin__project__owner_id=str(user.get('user_id'))).first() or TwinScenario.objects.filter(id=scenario_id,twin__project__members__id=str(user.get('user_id'))).first())()
    if not item: raise HTTPException(status_code=404,detail='Scenario not found')
    task=predict_digital_twin_scenario_task.delay(str(item.id)); return {'scenario_id':str(item.id),'task_id':task.id,'status':'queued'}

@router.post('/twins/{twin_id}/drift-check')
async def check_drift(twin_id:UUID,current_assets:List[dict],user=Depends(get_current_user)):
    twin=await sync_to_async(lambda:DigitalTwin.objects.filter(id=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(id=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    modeled=await sync_to_async(lambda:set(TwinNode.objects.filter(twin=twin,kind=TwinNode.Kind.ASSET).values_list('external_id',flat=True)))()
    observed={str(x.get('id')) for x in current_assets if x.get('id')}; missing=sorted(observed-modeled); extra=sorted(modeled-observed)
    return {'drift':len(missing)+len(extra),'missing_in_model':missing,'extra_in_model':extra,'status':'drift_detected' if missing or extra else 'in_sync'}
