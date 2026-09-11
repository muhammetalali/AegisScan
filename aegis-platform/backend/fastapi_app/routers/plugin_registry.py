from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from enterprise.models import PluginPackage
from ..core.dependencies import get_current_user
from ..services.external_fabric import (
    ExternalFabricError,
    activate_plugin_package,
    approve_plugin_package,
    dynamic_plugin_capabilities,
    register_plugin_package,
    resolve_plugin_dependencies,
)

router=APIRouter()


class PluginPackageIn(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=160)
    version:str=Field(min_length=1,max_length=80)
    source:str=Field(min_length=1,max_length=1000)
    digest:str=Field(pattern=r'^[0-9a-f]{64}$')
    manifest:dict=Field(default_factory=dict)
    dependencies:list[dict]=Field(default_factory=list,max_length=128)


def _staff(user:dict)->str:
    if not user.get('is_staff'):
        raise HTTPException(status_code=403,detail='Staff privileges required')
    user_id=user.get('user_id') or user.get('id')
    if not user_id:
        raise HTTPException(status_code=401,detail='Invalid authenticated user')
    return str(user_id)


@router.get('/packages')
async def list_plugin_packages(user=Depends(get_current_user)):
    _staff(user)
    rows=await sync_to_async(lambda:list(PluginPackage.objects.order_by('name','-installed_at').values(
        'id','name','version','source','digest','manifest','dependencies','approved','enabled','installed_at','updated_at'
    )))()
    return [
        {
            **row,
            'id':str(row['id']),
            'installed_at':row['installed_at'].isoformat(),
            'updated_at':row['updated_at'].isoformat(),
        }
        for row in rows
    ]


@router.post('/packages',status_code=201)
async def create_plugin_package(payload:PluginPackageIn,user=Depends(get_current_user)):
    _staff(user)
    try:
        package=await sync_to_async(register_plugin_package)(**payload.model_dump())
    except ExternalFabricError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return {
        'id':str(package.id),'name':package.name,'version':package.version,
        'approved':package.approved,'enabled':package.enabled,'digest':package.digest,
    }


@router.post('/packages/{package_id}/approve')
async def approve_plugin(package_id:UUID,user=Depends(get_current_user)):
    _staff(user)
    try:
        package=await sync_to_async(approve_plugin_package)(str(package_id))
    except (ExternalFabricError,PluginPackage.DoesNotExist) as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return {'id':str(package.id),'approved':package.approved,'enabled':package.enabled}


@router.post('/packages/{package_id}/activate')
async def activate_plugin(package_id:UUID,user=Depends(get_current_user)):
    _staff(user)
    try:
        package=await sync_to_async(activate_plugin_package)(str(package_id))
        resolution=await sync_to_async(resolve_plugin_dependencies)(package)
    except (ExternalFabricError,PluginPackage.DoesNotExist) as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    return {
        'id':str(package.id),'name':package.name,'version':package.version,
        'approved':package.approved,'enabled':package.enabled,'dependency_resolution':resolution,
    }


@router.get('/capabilities')
async def plugin_capabilities(user=Depends(get_current_user)):
    _staff(user)
    try:
        items=await sync_to_async(dynamic_plugin_capabilities)()
    except ExternalFabricError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    return {'capabilities':items}
