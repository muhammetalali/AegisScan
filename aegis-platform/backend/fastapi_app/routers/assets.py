from typing import List, Optional
import csv
import io
import json

from asgiref.sync import sync_to_async
from django.db import transaction
from django.db.models import Q
from django.utils.text import slugify
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Query
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..core.dependencies import get_current_user
from ..services.scope_authorization import ScopeAuthorizationError, require_authorized_target

router = APIRouter()


class AssetCreate(BaseModel):
    project_id: str
    name: str
    type: str
    description: str = ''
    environment: str = 'development'
    criticality: str = 'medium'
    configuration: dict = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class AssetResponse(BaseModel):
    id: str; project_id: str; name: str; slug: str; type: str; description: str; environment: str; criticality: str; configuration: dict; tags: List[str]; is_active: bool; scan_count: int; last_scanned_at: Optional[str] = None; created_at: str; updated_at: str


class AssetUpdate(BaseModel):
    name: Optional[str] = None; description: Optional[str] = None; environment: Optional[str] = None; criticality: Optional[str] = None; configuration: Optional[dict] = None; tags: Optional[List[str]] = None; is_active: Optional[bool] = None


def _asset_response(asset) -> AssetResponse:
    return AssetResponse(id=str(asset.id), project_id=str(asset.project_id), name=asset.name, slug=asset.slug, type=asset.type, description=asset.description, environment=asset.environment, criticality=asset.criticality, configuration=asset.configuration or {}, tags=asset.tags or [], is_active=asset.is_active, scan_count=asset.scan_count, last_scanned_at=asset.last_scanned_at.isoformat() if asset.last_scanned_at else None, created_at=asset.created_at.isoformat(), updated_at=asset.updated_at.isoformat())


@sync_to_async
def _accessible_assets(user_id: str, project_id: Optional[str] = None):
    from django_project.assets.models import Asset
    owner_qs=Asset.objects.select_related('project','owner').filter(project__owner_id=user_id); member_qs=Asset.objects.select_related('project','owner').filter(project__members__id=user_id); qs=(owner_qs|member_qs).distinct()
    if project_id: qs=qs.filter(project_id=project_id)
    return list(qs.order_by('-created_at'))


@sync_to_async
def _has_project_access(project_id: str, user_id: str) -> bool:
    from django_project.projects.models import Project
    return Project.objects.filter(id=project_id).filter(Q(owner_id=user_id)|Q(members__id=user_id)).exists()


@sync_to_async
def _get_asset(asset_id: str, user_id: str):
    from django_project.assets.models import Asset
    return Asset.objects.select_related('project','owner').filter(pk=asset_id).filter(Q(project__owner_id=user_id)|Q(project__members__id=user_id)).first()


@router.get('/', response_model=List[AssetResponse])
async def list_assets(project_id: Optional[str]=None, asset_type: Optional[str]=None, environment: Optional[str]=None, criticality: Optional[str]=None, is_active: Optional[bool]=None, search: Optional[str]=None, limit: int=Query(50,ge=1,le=200), offset: int=Query(0,ge=0), user=Depends(get_current_user)):
    assets=await _accessible_assets(str(user.get('user_id')),project_id)
    if asset_type: assets=[a for a in assets if a.type==asset_type]
    if environment: assets=[a for a in assets if a.environment==environment]
    if criticality: assets=[a for a in assets if a.criticality==criticality]
    if is_active is not None: assets=[a for a in assets if a.is_active==is_active]
    if search:
        needle=search.casefold(); assets=[a for a in assets if needle in a.name.casefold() or needle in a.description.casefold() or any(needle in str(t).casefold() for t in (a.tags or []))]
    return [_asset_response(a) for a in assets[offset:offset+limit]]


@sync_to_async
def _create_asset(data: AssetCreate, user_id: str):
    from django_project.assets.models import Asset
    from django_project.projects.models import Project
    project=Project.objects.filter(id=data.project_id).filter(Q(owner_id=user_id)|Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404,detail='Project not found or inaccessible')
    base_slug=slugify(data.name) or 'asset'; slug=base_slug; suffix=2
    while Asset.objects.filter(project=project,slug=slug).exists(): slug=f'{base_slug}-{suffix}'; suffix+=1
    return Asset.objects.create(project=project,owner_id=user_id,name=data.name,slug=slug,type=data.type,description=data.description,environment=data.environment,criticality=data.criticality,configuration=data.configuration,tags=data.tags)


@router.post('/', response_model=AssetResponse, status_code=201)
async def create_asset(asset: AssetCreate, user=Depends(get_current_user)):
    return _asset_response(await _create_asset(asset,str(user.get('user_id'))))


@router.get('/{asset_id}', response_model=AssetResponse)
async def get_asset(asset_id: str, user=Depends(get_current_user)):
    asset=await _get_asset(asset_id,str(user.get('user_id')))
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    return _asset_response(asset)


@sync_to_async
def _update_asset(asset_id: str, update: AssetUpdate, user_id: str):
    asset=_get_asset_sync(asset_id,user_id)
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    data=update.model_dump(exclude_unset=True)
    if 'name' in data: data['slug']=slugify(data['name']) or asset.slug
    for key,value in data.items(): setattr(asset,key,value)
    asset.save(); return asset


def _get_asset_sync(asset_id: str,user_id: str):
    from django_project.assets.models import Asset
    return Asset.objects.filter(pk=asset_id).filter(Q(project__owner_id=user_id)|Q(project__members__id=user_id)).first()


@router.patch('/{asset_id}', response_model=AssetResponse)
async def update_asset(asset_id: str, update: AssetUpdate, user=Depends(get_current_user)): return _asset_response(await _update_asset(asset_id,update,str(user.get('user_id'))))


@sync_to_async
def _delete_asset(asset_id: str,user_id: str):
    asset=_get_asset_sync(asset_id,user_id)
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    asset.delete()


@router.delete('/{asset_id}')
async def delete_asset(asset_id: str,user=Depends(get_current_user)):
    await _delete_asset(asset_id,str(user.get('user_id'))); return {'deleted':True,'asset_id':asset_id}


@router.post('/{asset_id}/scan')
async def scan_asset(asset_id: str, scan_type: Optional[str]=None, depth: str='standard', user=Depends(get_current_user)):
    asset=await _get_asset(asset_id,str(user.get('user_id')))
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    config=asset.configuration or {}
    if config.get('authorized') is not True: raise HTTPException(status_code=403,detail='Asset must be explicitly authorized for scanner execution')
    from .scans import ScanCreate,_create_scan,_attach_celery_task,run_masscan_scan,run_nmap_scan,run_nuclei_scan,run_semgrep_scan
    type_to_scan={'website':('url','nuclei'),'ip_address':('ip','nmap'),'domain':('ip','nmap'),'network_range':('network','masscan'),'source_code':('code','semgrep'),'repository':('code','semgrep'),'api_endpoint':('url','nuclei')}
    inferred=type_to_scan.get(asset.type)
    if not inferred: raise HTTPException(status_code=400,detail=f'No scanner mapping exists for asset type: {asset.type}')
    resolved_type,engine=inferred
    final_scan_type=scan_type or resolved_type
    if final_scan_type!=resolved_type: raise HTTPException(status_code=400,detail=f'Asset type {asset.type} requires scan_type={resolved_type}')
    config_target=config.get('url') or config.get('host') or config.get('ip') or config.get('domain') or config.get('cidr') or config.get('path') or config.get('repo_url')
    if engine in {'nmap','nuclei','masscan'} and not config_target: raise HTTPException(status_code=400,detail='Asset has no executable target in configuration')
    if engine in {'nmap','nuclei','masscan'}:
        try:
            require_authorized_target(str(config_target))
        except ScopeAuthorizationError as exc:
            raise HTTPException(status_code=403,detail=str(exc)) from exc
    created,engines=await _create_scan(ScanCreate(project_id=str(asset.project_id),name=f'Asset scan: {asset.name}',scan_type=final_scan_type,asset_id=str(asset.id),engines=[engine],depth=depth,config={**config,'target':config_target},authorized=True),str(user.get('user_id')))
    task_map={'nmap':run_nmap_scan,'nuclei':run_nuclei_scan,'masscan':run_masscan_scan,'semgrep':run_semgrep_scan}; result=task_map[engine].delay(str(created.id)); created=await _attach_celery_task(str(created.id),result.id)
    return {'scan_id':str(created.id),'task_id':result.id,'engine':engine,'status':created.status,'source':'postgresql'}


@sync_to_async
def _technologies(asset_id: str,user_id: str):
    asset=_get_asset_sync(asset_id,user_id); return list(asset.technologies.all()) if asset else None


@router.get('/{asset_id}/technologies')
async def get_asset_technologies(asset_id: str,user=Depends(get_current_user)):
    technologies=await _technologies(asset_id,str(user.get('user_id')))
    if technologies is None: raise HTTPException(status_code=404,detail='Asset not found')
    return [{'id':str(t.id),'name':t.name,'version':t.version,'category':t.category,'confidence':t.confidence,'source':t.source,'evidence':t.evidence,'detected_at':t.detected_at.isoformat()} for t in technologies]


@router.post('/{asset_id}/technologies')
async def add_technology(asset_id: str,name: str,version: str='',category: str='unknown',confidence: float=0.0,user=Depends(get_current_user)):
    from django_project.assets.models import TechnologyFingerprint
    asset=await _get_asset(asset_id,str(user.get('user_id')))
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    technology=await sync_to_async(TechnologyFingerprint.objects.create)(asset=asset,name=name,version=version,category=category,confidence=confidence,source='manual'); return {'id':str(technology.id),'created':True}


@router.get('/{asset_id}/relationships')
async def get_asset_relationships(asset_id: str,user=Depends(get_current_user)):
    from django_project.assets.models import AssetRelationship
    asset=await _get_asset(asset_id,str(user.get('user_id')))
    if not asset: raise HTTPException(status_code=404,detail='Asset not found')
    relationships=await sync_to_async(list)(AssetRelationship.objects.filter(source=asset).select_related('target')); return [{'id':str(r.id),'target_id':str(r.target_id),'relationship_type':r.relationship_type,'metadata':r.metadata,'created_at':r.created_at.isoformat()} for r in relationships]


@router.post('/{asset_id}/relationships')
async def add_relationship(asset_id: str,target_id: str,relationship_type: str,user=Depends(get_current_user)):
    from django_project.assets.models import AssetRelationship
    source=await _get_asset(asset_id,str(user.get('user_id'))); target=await _get_asset(target_id,str(user.get('user_id')))
    if not source or not target or source.project_id!=target.project_id: raise HTTPException(status_code=404,detail='Source or target asset not found')
    relationship,created=await sync_to_async(AssetRelationship.objects.get_or_create)(project_id=source.project_id,source=source,target=target,relationship_type=relationship_type); return {'id':str(relationship.id),'created':created}


def _normalize_import_row(row: dict[str,object],project_id: str) -> AssetCreate:
    config=dict(row.get('configuration') or {}) if isinstance(row.get('configuration'),dict) else {}
    for key in ('url','host','ip','domain','cidr','repo_url','path','services','authorized'):
        if key in row and key not in config: config[key]=row[key]
    if config.get('authorized') is not True: config['authorized']=False
    tags=row.get('tags') if isinstance(row.get('tags'),list) else [x.strip() for x in str(row.get('tags') or '').split(',') if x.strip()]
    name=str(row.get('name') or row.get('target') or row.get('url') or row.get('host') or row.get('domain') or '').strip()
    asset_type=str(row.get('type') or '').strip();
    if not name or not asset_type: raise ValueError('Each import row requires name and type')
    return AssetCreate(project_id=project_id,name=name,type=asset_type,description=str(row.get('description') or ''),environment=str(row.get('environment') or 'development'),criticality=str(row.get('criticality') or 'medium'),configuration=config,tags=tags)


@router.post('/bulk-import', response_model=List[AssetResponse], status_code=201)
async def bulk_import_assets(project_id: str,file: UploadFile=File(...),user=Depends(get_current_user)):
    user_id=str(user.get('user_id'))
    if not await _has_project_access(project_id,user_id): raise HTTPException(status_code=404,detail='Project not found or inaccessible')
    raw=await file.read()
    if len(raw)>5*1024*1024: raise HTTPException(status_code=413,detail='Import file exceeds 5 MiB limit')
    try:
        text=raw.decode('utf-8-sig')
        content_type=(file.content_type or '').lower()
        if (file.filename and file.filename.lower().endswith('.csv')) or 'csv' in content_type:
            rows=list(csv.DictReader(io.StringIO(text)))
        else:
            parsed=json.loads(text); rows=parsed if isinstance(parsed,list) else parsed.get('assets',[]) if isinstance(parsed,dict) else []
        if not isinstance(rows,list) or not rows: raise ValueError('Import payload must contain a non-empty array of assets')
        if len(rows)>1000: raise ValueError('Import payload may contain at most 1000 assets')
        normalized=[_normalize_import_row(row,project_id) for row in rows if isinstance(row,dict)]
    except (UnicodeDecodeError,json.JSONDecodeError,ValueError,TypeError) as exc: raise HTTPException(status_code=400,detail=f'Invalid asset import payload: {exc}') from exc
    try:
        created = await _bulk_create_assets(normalized, user_id)
    except HTTPException:
        raise
    return [_asset_response(asset) for asset in created]


@sync_to_async
@transaction.atomic
def _bulk_create_assets(items: List[AssetCreate], user_id: str):
    from django_project.assets.models import Asset
    from django_project.projects.models import Project
    projects={str(project.id): project for project in Project.objects.filter(id__in={item.project_id for item in items}).filter(Q(owner_id=user_id)|Q(members__id=user_id)).distinct()}
    created=[]
    for item in items:
        project=projects.get(item.project_id)
        if not project: raise HTTPException(status_code=404,detail='Project not found or inaccessible')
        base_slug=slugify(item.name) or 'asset'; slug=base_slug; suffix=2
        while Asset.objects.filter(project=project,slug=slug).exists(): slug=f'{base_slug}-{suffix}'; suffix+=1
        created.append(Asset(project=project,owner_id=user_id,name=item.name,slug=slug,type=item.type,description=item.description,environment=item.environment,criticality=item.criticality,configuration=item.configuration,tags=item.tags))
    Asset.objects.bulk_create(created)
    return created

# verify_token remains imported for compatibility with deployments that import this module symbolically.
_ = verify_token
