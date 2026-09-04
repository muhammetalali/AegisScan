from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..core.dependencies import get_current_user
from django_project.projects.models import Project
from enterprise.models import ExternalIntegration, Notification, SBOMArtifact
from enterprise.services import ensure_project_tenant
from enterprise.tasks import dispatch_integration, ingest_sbom_task, send_notification

router=APIRouter()

class NotificationCreate(BaseModel):
    project_id:UUID
    channel:str
    event_type:str
    payload:dict[str,Any]=Field(default_factory=dict)
    user_id:UUID|None=None

class IntegrationCreate(BaseModel):
    project_id:UUID
    kind:str
    name:str
    base_url:str
    secret_ref:str=''
    config:dict[str,Any]=Field(default_factory=dict)

class SBOMCreate(BaseModel):
    project_id:UUID
    source:str
    source_ref:str
    document:dict[str,Any]

async def _project(project_id:UUID,user):
    project=await sync_to_async(lambda:Project.objects.filter(id=project_id,owner_id=str(user.get('user_id'))).first() or Project.objects.filter(id=project_id,members__id=str(user.get('user_id'))).first())()
    if not project: raise HTTPException(status_code=404,detail='Project not found or inaccessible')
    return project

@sync_to_async
def _notifications(user_id:str,project_id:Optional[str],status:Optional[str],limit:int,offset:int):
    access = Q(user_id=user_id) | Q(user__isnull=True, organization__memberships__user_id=user_id, organization__memberships__is_active=True)
    qs=Notification.objects.filter(access).distinct().order_by('-created_at')
    if status: qs=qs.filter(status=status)
    if project_id:
        qs=qs.filter(organization__project_links__project_id=project_id)
    return list(qs[offset:offset+limit])


def _notification_json(item:Notification):
    return {
        'id':str(item.id),
        'channel':item.channel,
        'event_type':item.event_type,
        'payload':item.payload or {},
        'status':item.status,
        'attempts':item.attempts,
        'last_error':item.last_error or None,
        'sent_at':item.sent_at.isoformat() if item.sent_at else None,
        'created_at':item.created_at.isoformat(),
    }

@router.get('/notifications')
async def list_notifications(project_id:Optional[str]=None,status:Optional[str]=None,limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),user=Depends(get_current_user)):
    return [_notification_json(item) for item in await _notifications(str(user.get('user_id')),project_id,status,limit,offset)]

@router.get('/notifications/{notification_id}')
async def get_notification(notification_id:UUID,user=Depends(get_current_user)):
    rows=await _notifications(str(user.get('user_id')),None,None,200,0)
    for item in rows:
        if item.id == notification_id:
            return _notification_json(item)
    raise HTTPException(status_code=404,detail='Notification not found')

@router.post('/notifications',status_code=202)
async def create_notification(body:NotificationCreate,user=Depends(get_current_user)):
    project=await _project(body.project_id,user); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id')))
    item=await sync_to_async(Notification.objects.create)(organization=org,user_id=str(body.user_id) if body.user_id else str(user.get('user_id')),channel=body.channel,event_type=body.event_type,payload=body.payload)
    task=send_notification.delay(str(item.id)); return {'id':str(item.id),'task_id':task.id,'status':item.status}

@router.post('/integrations',status_code=201)
async def create_integration(body:IntegrationCreate,user=Depends(get_current_user)):
    project=await _project(body.project_id,user); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id')))
    kind=body.kind
    if kind not in set(ExternalIntegration.Kind.values): raise HTTPException(status_code=400,detail='Unsupported integration kind')
    item=await sync_to_async(ExternalIntegration.objects.create)(organization=org,kind=kind,name=body.name,base_url=body.base_url,secret_ref=body.secret_ref,config=body.config,created_by_id=str(user.get('user_id')))
    return {'id':str(item.id),'organization_id':str(org.id),'kind':item.kind,'enabled':item.enabled}

@router.post('/integrations/{integration_id}/test',status_code=202)
async def test_integration(integration_id:UUID,event:dict[str,Any],user=Depends(get_current_user)):
    item=await sync_to_async(lambda:ExternalIntegration.objects.filter(id=integration_id,organization__memberships__user_id=str(user.get('user_id')),organization__memberships__is_active=True).first())()
    if not item: raise HTTPException(status_code=404,detail='Integration not found')
    task=dispatch_integration.delay(str(item.id),event); return {'integration_id':str(item.id),'task_id':task.id}

@router.post('/sbom',status_code=202)
async def ingest_sbom(body:SBOMCreate,user=Depends(get_current_user)):
    project=await _project(body.project_id,user); org=await sync_to_async(ensure_project_tenant)(project,str(user.get('user_id')))
    task=ingest_sbom_task.delay(str(project.id),str(org.id),body.source,body.source_ref,body.document,str(user.get('user_id')))
    return {'project_id':str(project.id),'task_id':task.id,'status':'queued'}

@router.get('/projects/{project_id}/sbom')
async def list_sbom(project_id:UUID,user=Depends(get_current_user)):
    await _project(project_id,user)
    rows=await sync_to_async(lambda:list(SBOMArtifact.objects.filter(project_id=project_id).values('id','source','source_ref','format','sha256','component_count','created_at')))()
    return [{'id':str(x['id']),**{k:v for k,v in x.items() if k!='id'}} for x in rows]
