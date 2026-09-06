from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from django.utils import timezone

from enterprise.models import (
    AttackPath, CloudDiscoveryRun, ComplianceMapping, DigitalTwin, ExecutiveSnapshot,
    ExternalIntegration, FindingIntelligence, Notification, Organization, OrganizationMembership,
    SBOMArtifact, SBOMComponent, TwinScenario, TenantProject,
    ContinuousAssuranceExecution, ContinuousAssuranceSchedule,
)
from enterprise.services import ensure_project_tenant, build_twin, predict_scenario, generate_attack_paths, map_compliance, executive_snapshot
from enterprise.tasks import build_digital_twin_task, predict_digital_twin_scenario_task, generate_attack_paths_task, map_compliance_task, claim_continuous_assurance_execution, run_continuous_assurance
from django_project.projects.models import Project
from django_project.users.models import Permission
from fastapi_app.core.dependencies import require_permission

router = APIRouter()

class OrgCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=220, pattern=r'^[a-z0-9-]+$')
class TwinCreate(BaseModel):
    project_id: UUID
    name: str
class ScenarioCreate(BaseModel):
    name: str
    change_type: str
    description: str = ''
    affected_nodes: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
class ScheduleCreate(BaseModel):
    project_id: UUID
    title: str
    report_type: str = 'full'
    format: str = 'pdf'
    frequency: str
    recipients: list[str] = Field(default_factory=list)
    next_run: Optional[datetime] = None
class ContinuousAssuranceCreate(BaseModel):
    project_id: UUID
    asset_id: UUID
    scan_type: str
    engine: str
    interval_minutes: int = Field(default=60, ge=5, le=43200)
    next_run: Optional[datetime] = None

@sync_to_async
def _project_for_user(project_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(owner_id=user_id).first() or Project.objects.filter(id=project_id, members__id=user_id).first()
    if not project: raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project


@sync_to_async
def _tenant_for_user(project: Project, user_id: str):
    try:
        return ensure_project_tenant(project,user_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403,detail=str(exc)) from exc

@router.get('/organizations')
async def organizations(user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    return await sync_to_async(lambda: [{'id':str(m.organization_id),'name':m.organization.name,'slug':m.organization.slug,'role':m.role} for m in OrganizationMembership.objects.filter(user_id=str(user.get('user_id')),is_active=True).select_related('organization')])()

@router.post('/organizations', status_code=201)
async def create_organization(body: OrgCreate, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    def create():
        from django_project.users.models import User
        u=User.objects.get(pk=str(user.get('user_id'))); org=Organization.objects.create(name=body.name,slug=body.slug,owner=u); OrganizationMembership.objects.create(organization=org,user=u,role=OrganizationMembership.Role.OWNER); return {'id':str(org.id),'name':org.name,'slug':org.slug,'role':OrganizationMembership.Role.OWNER}
    return await sync_to_async(create)()

@router.post('/projects/{project_id}/tenant')
async def bind_project_tenant(project_id: UUID, organization_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    project=await _project_for_user(str(project_id),str(user.get('user_id')))
    def bind():
        org=Organization.objects.filter(pk=organization_id).first()
        if not org: raise HTTPException(status_code=404, detail='Organization not found')
        if not OrganizationMembership.objects.filter(organization=org,user_id=str(user.get('user_id')),role__in=[OrganizationMembership.Role.OWNER,OrganizationMembership.Role.ADMIN],is_active=True).exists(): raise HTTPException(status_code=403, detail='Organization administration permission required')
        link,created=TenantProject.objects.update_or_create(project=project,defaults={'organization':org})
        OrganizationMembership.objects.get_or_create(organization=org,user=project.owner,defaults={'role':OrganizationMembership.Role.OWNER})
        return {'project_id':str(project.id),'organization_id':str(link.organization_id),'created':created}
    return await sync_to_async(bind)()

@router.post('/twins')
async def create_twin(body: TwinCreate, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    project=await _project_for_user(str(body.project_id),str(user.get('user_id'))); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id'))); twin=await sync_to_async(DigitalTwin.objects.create)(organization=org,project=project,name=body.name); task=build_digital_twin_task.delay(str(twin.id)); return {'id':str(twin.id),'project_id':str(project.id),'organization_id':str(org.id),'task_id':task.id,'status':twin.status}

@router.get('/twins/{twin_id}')
async def get_twin(twin_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    twin=await sync_to_async(lambda: DigitalTwin.objects.filter(pk=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(pk=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    return {'id':str(twin.id),'project_id':str(twin.project_id),'organization_id':str(twin.organization_id),'name':twin.name,'status':twin.status,'version':twin.version,'snapshot':twin.snapshot,'built_at':twin.built_at.isoformat() if twin.built_at else None}

@router.post('/twins/{twin_id}/build')
async def build_twin_endpoint(twin_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    twin=await sync_to_async(lambda: DigitalTwin.objects.filter(pk=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(pk=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    return {'task_id':build_digital_twin_task.delay(str(twin.id)).id,'twin_id':str(twin.id)}

@router.post('/twins/{twin_id}/scenarios', status_code=201)
async def create_scenario(twin_id: UUID, body: ScenarioCreate, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    twin=await sync_to_async(lambda: DigitalTwin.objects.filter(pk=twin_id,project__owner_id=str(user.get('user_id'))).first() or DigitalTwin.objects.filter(pk=twin_id,project__members__id=str(user.get('user_id'))).first())()
    if not twin: raise HTTPException(status_code=404,detail='Digital Twin not found')
    scenario=await sync_to_async(TwinScenario.objects.create)(twin=twin,name=body.name,change_type=body.change_type,description=body.description,affected_nodes=body.affected_nodes,parameters=body.parameters,created_by_id=str(user.get('user_id'))); task=predict_digital_twin_scenario_task.delay(str(scenario.id)); return {'id':str(scenario.id),'task_id':task.id,'status':scenario.status}

@router.get('/twins/{twin_id}/scenarios')
async def list_scenarios(twin_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    rows=await sync_to_async(lambda:list(TwinScenario.objects.filter(twin_id=twin_id,twin__project__owner_id=str(user.get('user_id'))).values('id','name','change_type','baseline_risk','predicted_risk','risk_delta','status','recommendation','evidence')))(); return [{'id':str(x['id']),**{k:v for k,v in x.items() if k!='id'}} for x in rows]

@router.post('/projects/{project_id}/attack-paths')
async def create_attack_paths(project_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    project=await _project_for_user(str(project_id),str(user.get('user_id'))); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id'))); task=generate_attack_paths_task.delay(str(project.id),str(org.id)); return {'task_id':task.id,'status':'queued'}

@router.get('/projects/{project_id}/attack-paths')
async def list_attack_paths(project_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    await _project_for_user(str(project_id),str(user.get('user_id'))); rows=await sync_to_async(lambda:list(AttackPath.objects.filter(project_id=project_id).values('id','source_node','target_node','steps','risk_score','status','evidence','discovered_at')))(); return [{'id':str(x['id']),**{k:v for k,v in x.items() if k!='id'}} for x in rows]

@router.post('/projects/{project_id}/compliance/map')
async def automatic_compliance_map(project_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    await _project_for_user(str(project_id),str(user.get('user_id'))); task=map_compliance_task.delay(str(project_id)); return {'task_id':task.id,'status':'queued'}

@router.get('/projects/{project_id}/compliance/mappings')
async def compliance_mappings(project_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    await _project_for_user(str(project_id),str(user.get('user_id'))); rows=await sync_to_async(lambda:list(ComplianceMapping.objects.filter(assessment__project_id=project_id).values('id','assessment_id','vulnerability_id','mapping_reason','confidence','source')))(); return [{'id':str(x['id']),**{k:v for k,v in x.items() if k!='id'}} for x in rows]

@router.get('/projects/{project_id}/executive')
async def executive(project_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    project=await _project_for_user(str(project_id),str(user.get('user_id'))); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id'))); snap=await sync_to_async(executive_snapshot)(project,org); return {'id':str(snap.id),'score':snap.score,'risk':snap.risk,'critical_findings':snap.critical_findings,'high_findings':snap.high_findings,'open_findings':snap.open_findings,'validated_findings':snap.validated_findings,'fixed_findings':snap.fixed_findings,'compliance_score':snap.compliance_score,'coverage_score':snap.coverage_score,'trend':snap.trend,'deltas':snap.deltas,'source_scan_id':str(snap.source_scan_id) if snap.source_scan_id else None}

@router.post('/report-schedules', status_code=201, deprecated=True)
async def create_report_schedule(body: ScheduleCreate, user=Depends(require_permission(Permission.REPORT_CREATE))):
    from fastapi_app.routers.reports import ReportScheduleCreate, _create_report_schedules, _serialize_schedule
    await _project_for_user(str(body.project_id),str(user.get('user_id')))
    rows=await _create_report_schedules(ReportScheduleCreate(
        project_id=str(body.project_id),template_id=body.report_type,frequency=body.frequency,
        recipients=body.recipients,formats=[body.format],title=body.title,next_run=body.next_run,
    ),str(user.get('user_id')))
    return _serialize_schedule(rows[0])

@router.get('/report-schedules/{schedule_id}', deprecated=True)
async def get_report_schedule(schedule_id: UUID, user=Depends(require_permission(Permission.REPORT_READ))):
    from fastapi_app.routers.reports import _get_report_schedule, _serialize_schedule
    return _serialize_schedule(await _get_report_schedule(str(schedule_id),str(user.get('user_id'))))

@router.post('/continuous-assurance/{schedule_id}/run')
async def run_assurance(schedule_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    schedule=await sync_to_async(lambda:ContinuousAssuranceSchedule.objects.select_related('project').filter(pk=schedule_id).first())()
    if not schedule: raise HTTPException(status_code=404,detail='Continuous assurance schedule not found')
    project=await _project_for_user(str(schedule.project_id),str(user.get('user_id')))
    org=await _tenant_for_user(project,str(user.get('user_id')))
    if org.id != schedule.organization_id:
        raise HTTPException(status_code=404,detail='Continuous assurance schedule not found')
    execution,_=await sync_to_async(claim_continuous_assurance_execution)(str(schedule.id))
    if execution is None:
        raise HTTPException(status_code=409,detail='Continuous assurance schedule has no durable authorization binding')
    task=run_continuous_assurance.delay(str(execution.id))
    await sync_to_async(ContinuousAssuranceExecution.objects.filter(pk=execution.id).update)(celery_task_id=task.id)
    return {'task_id':task.id,'execution_id':str(execution.id),'schedule_id':str(schedule.id),'status':'queued'}


@router.get('/continuous-assurance')
async def list_continuous_assurance(user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    user_id=str(user.get('user_id'))
    def load():
        schedules=(ContinuousAssuranceSchedule.objects.filter(
            Q(project__owner_id=user_id)|Q(project__memberships__user_id=user_id),
            organization__memberships__user_id=user_id,
            organization__memberships__is_active=True,
        ).select_related('organization','project','asset','authorization_decision').distinct().order_by('-created_at'))
        rows=[]
        for schedule in schedules:
            execution=schedule.executions.select_related('scan').order_by('-scheduled_for','-created_at').first()
            rows.append({
                'id':str(schedule.id),'organization_id':str(schedule.organization_id),'project_id':str(schedule.project_id),
                'project_name':schedule.project.name,'asset_id':str(schedule.asset_id) if schedule.asset_id else None,
                'asset_name':schedule.asset.name if schedule.asset_id else None,'authorization_decision_id':str(schedule.authorization_decision_id) if schedule.authorization_decision_id else None,
                'scan_type':schedule.scan_type,'engine':schedule.engine,'interval_minutes':schedule.interval_minutes,
                'enabled':schedule.enabled,'next_run':schedule.next_run.isoformat(),'last_run':schedule.last_run.isoformat() if schedule.last_run else None,
                'disabled_at':schedule.disabled_at.isoformat() if schedule.disabled_at else None,'disabled_reason':schedule.disabled_reason,
                'latest_execution':None if execution is None else {
                    'id':str(execution.id),'status':execution.status,'scheduled_for':execution.scheduled_for.isoformat(),
                    'scan_id':str(execution.scan_id) if execution.scan_id else None,'reason':execution.reason,
                    'attempts':execution.attempts,'completed_at':execution.completed_at.isoformat() if execution.completed_at else None,
                },
            })
        return rows
    return await sync_to_async(load)()

@router.post('/continuous-assurance', status_code=201)
async def create_continuous_assurance(body: ContinuousAssuranceCreate, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    from django_project.assets.models import Asset
    from fastapi_app.services.authorization_guard import current_asset_authorization
    if body.engine not in {'nmap','nuclei','masscan','semgrep'}:
        raise HTTPException(status_code=400, detail='Unsupported continuous assurance engine')
    project=await _project_for_user(str(body.project_id),str(user.get('user_id')))
    org=await _tenant_for_user(project,str(user.get('user_id')))
    asset=await sync_to_async(lambda:Asset.objects.filter(pk=body.asset_id,project=project,is_active=True).first())()
    if not asset:
        raise HTTPException(status_code=404,detail='Active project asset not found')
    from fastapi_app.services.continuous_assurance import validate_assurance_engine_contract
    engine_contract_error=validate_assurance_engine_contract(asset,body.scan_type,body.engine)
    if engine_contract_error:
        raise HTTPException(status_code=422,detail=engine_contract_error)
    authorization,reason=await sync_to_async(current_asset_authorization)(asset)
    if authorization is None:
        raise HTTPException(status_code=403,detail=reason)
    next_run=body.next_run or timezone.now()
    if timezone.is_naive(next_run):
        next_run=timezone.make_aware(next_run,timezone.get_current_timezone())
    schedule=await sync_to_async(ContinuousAssuranceSchedule.objects.create)(organization=org,project=project,asset=asset,authorization_decision=authorization,scan_type=body.scan_type,engine=body.engine,interval_minutes=body.interval_minutes,next_run=next_run,created_by_id=str(user.get('user_id')))
    return {'id':str(schedule.id),'project_id':str(project.id),'asset_id':str(asset.id),'authorization_decision_id':str(authorization.id),'next_run':schedule.next_run.isoformat(),'enabled':schedule.enabled}

@router.post('/projects/{project_id}/cloud-discovery', status_code=202)
async def cloud_discovery(project_id: UUID, provider: str, config: dict[str,Any], user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    project=await _project_for_user(str(project_id),str(user.get('user_id'))); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id'))); run=await sync_to_async(CloudDiscoveryRun.objects.create)(organization=org,project=project,provider=provider,config=config,created_by_id=str(user.get('user_id')))
    from enterprise.tasks import cloud_discovery_task
    task=cloud_discovery_task.delay(str(run.id)); return {'run_id':str(run.id),'task_id':task.id}

@router.get('/projects/{project_id}/cloud-discovery/{run_id}')
async def cloud_discovery_status(project_id: UUID, run_id: UUID, user=Depends(__import__('fastapi_app.core.dependencies',fromlist=['get_current_user']).get_current_user)):
    await _project_for_user(str(project_id),str(user.get('user_id'))); run=await sync_to_async(lambda:CloudDiscoveryRun.objects.filter(pk=run_id,project_id=project_id).first())()
    if not run: raise HTTPException(status_code=404,detail='Cloud discovery run not found')
    return {'id':str(run.id),'provider':run.provider,'status':run.status,'resources':run.resources,'error_message':run.error_message,'started_at':run.started_at.isoformat() if run.started_at else None,'completed_at':run.completed_at.isoformat() if run.completed_at else None}
