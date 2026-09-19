from __future__ import annotations

from datetime import datetime

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import ScheduledScan, ScheduledScanExecution

from ..core.dependencies import get_current_user
from ..services.scheduled_execution import (
    ScheduledExecutionError,
    create_canonical_schedule,
    update_canonical_schedule,
)


router = APIRouter()


class ScheduledScanCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    project_id: str
    asset_id: str
    name: str = Field(min_length=1, max_length=200)
    capability_id: str = Field(min_length=1, max_length=120)
    depth: str = 'standard'
    options: dict = Field(default_factory=dict)
    credential_refs: list[str] = Field(default_factory=list, max_length=3)
    frequency: str = 'weekly'
    cron_expression: str = Field(default='', max_length=100)
    timezone: str = Field(default='UTC', min_length=1, max_length=64)
    first_run_at: datetime


class ScheduledScanUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    expected_version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    asset_id: str | None = None
    capability_id: str | None = Field(default=None, min_length=1, max_length=120)
    depth: str | None = None
    options: dict | None = None
    credential_refs: list[str] | None = Field(default=None, max_length=3)
    frequency: str | None = None
    cron_expression: str | None = Field(default=None, max_length=100)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    next_run_at: datetime | None = None
    is_active: bool | None = None


def _translate(exc: ScheduledExecutionError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={'code': exc.code, 'message': str(exc)},
    )


def _serialize_schedule(item: ScheduledScan) -> dict:
    return {
        'id': str(item.id),
        'name': item.name,
        'project_id': str(item.project_id),
        'asset_id': str(item.asset_id) if item.asset_id else None,
        'capability_id': item.capability_id,
        'depth': item.depth,
        'options': item.options if isinstance(item.options, dict) else {},
        'credential_refs': list(item.credential_refs or []),
        'policy_version': item.policy_version,
        'timezone': item.timezone,
        'frequency': item.frequency,
        'cron_expression': item.cron_expression,
        'next_run': item.next_run.isoformat(),
        'last_run': item.last_run.isoformat() if item.last_run else None,
        'is_active': item.is_active,
        'disabled_reason': item.disabled_reason,
        'version': item.version,
        'created_by_id': str(item.created_by_id) if item.created_by_id else None,
        'created_at': item.created_at.isoformat(),
        'updated_at': item.updated_at.isoformat(),
        'legacy_template_id': str(item.template_id) if item.template_id else None,
    }


def _serialize_execution(item: ScheduledScanExecution) -> dict:
    return {
        'id': str(item.id),
        'schedule_id': str(item.schedule_id),
        'scheduled_for': item.scheduled_for.isoformat(),
        'schedule_version': item.schedule_version,
        'project_id': str(item.project_id),
        'asset_id': str(item.asset_id),
        'authorization_decision_id': (
            str(item.authorization_decision_id) if item.authorization_decision_id else None
        ),
        'scan_id': str(item.scan_id) if item.scan_id else None,
        'capability_id': item.capability_id,
        'depth': item.depth_snapshot,
        'policy_version': item.policy_version_snapshot,
        'request_fingerprint': item.request_fingerprint,
        'policy_fingerprint': item.policy_fingerprint,
        'execution_contract_fingerprint': item.execution_contract_fingerprint,
        'correlation_id': item.correlation_id,
        'status': item.status,
        'attempts': item.attempts,
        'celery_task_id': item.celery_task_id,
        'scanner_task_id': item.scanner_task_id,
        'reason': item.reason,
        'started_at': item.started_at.isoformat() if item.started_at else None,
        'dispatched_at': item.dispatched_at.isoformat() if item.dispatched_at else None,
        'created_at': item.created_at.isoformat(),
        'updated_at': item.updated_at.isoformat(),
    }


@sync_to_async
def _create(payload: ScheduledScanCreate, user_id: str):
    return create_canonical_schedule(
        actor_id=user_id,
        project_id=payload.project_id,
        asset_id=payload.asset_id,
        name=payload.name,
        capability_id=payload.capability_id,
        depth=payload.depth,
        options=payload.options,
        credential_refs=payload.credential_refs,
        frequency=payload.frequency,
        cron_expression=payload.cron_expression,
        timezone_name=payload.timezone,
        first_run_at=payload.first_run_at,
    )


@sync_to_async
def _update(schedule_id: str, payload: ScheduledScanUpdate, user_id: str):
    return update_canonical_schedule(
        actor_id=user_id,
        schedule_id=schedule_id,
        expected_version=payload.expected_version,
        name=payload.name,
        asset_id=payload.asset_id,
        capability_id=payload.capability_id,
        depth=payload.depth,
        options=payload.options,
        credential_refs=payload.credential_refs,
        frequency=payload.frequency,
        cron_expression=payload.cron_expression,
        timezone_name=payload.timezone,
        next_run_at=payload.next_run_at,
        is_active=payload.is_active,
    )


@sync_to_async
def _list(user_id: str, project_id: str | None, active: bool | None, limit: int, offset: int):
    access = Q(project__owner_id=user_id) | Q(project__members__id=user_id)
    qs = (
        ScheduledScan.objects.select_related('project', 'asset', 'created_by')
        .filter(access)
        .distinct()
        .order_by('next_run', 'id')
    )
    if project_id:
        qs = qs.filter(project_id=project_id)
    if active is not None:
        qs = qs.filter(is_active=active)
    return list(qs[offset:offset + limit])


@sync_to_async
def _get(schedule_id: str, user_id: str):
    access = Q(project__owner_id=user_id) | Q(project__members__id=user_id)
    return (
        ScheduledScan.objects.select_related('project', 'asset', 'created_by')
        .filter(pk=schedule_id)
        .filter(access)
        .distinct()
        .first()
    )


@sync_to_async
def _executions(schedule_id: str, user_id: str, limit: int):
    access = Q(schedule__project__owner_id=user_id) | Q(schedule__project__members__id=user_id)
    return list(
        ScheduledScanExecution.objects.select_related('scan')
        .filter(schedule_id=schedule_id)
        .filter(access)
        .distinct()
        .order_by('-scheduled_for', '-created_at')[:limit]
    )


@router.post('/', status_code=201)
async def create_scheduled_scan(
    payload: ScheduledScanCreate,
    user=Depends(get_current_user),
):
    try:
        item = await _create(payload, str(user.get('user_id')))
    except ScheduledExecutionError as exc:
        raise _translate(exc) from exc
    return _serialize_schedule(item)


@router.get('/')
async def list_scheduled_scans(
    project_id: str | None = None,
    active: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
):
    items = await _list(str(user.get('user_id')), project_id, active, limit, offset)
    return {'results': [_serialize_schedule(item) for item in items]}


@router.get('/{schedule_id}')
async def get_scheduled_scan(
    schedule_id: str,
    user=Depends(get_current_user),
):
    item = await _get(schedule_id, str(user.get('user_id')))
    if item is None:
        raise HTTPException(status_code=404, detail='Scheduled scan not found')
    return _serialize_schedule(item)


@router.patch('/{schedule_id}')
async def update_scheduled_scan(
    schedule_id: str,
    payload: ScheduledScanUpdate,
    user=Depends(get_current_user),
):
    try:
        item = await _update(schedule_id, payload, str(user.get('user_id')))
    except ScheduledExecutionError as exc:
        raise _translate(exc) from exc
    return _serialize_schedule(item)


@router.get('/{schedule_id}/executions')
async def list_scheduled_scan_executions(
    schedule_id: str,
    limit: int = Query(50, ge=1, le=200),
    user=Depends(get_current_user),
):
    item = await _get(schedule_id, str(user.get('user_id')))
    if item is None:
        raise HTTPException(status_code=404, detail='Scheduled scan not found')
    executions = await _executions(schedule_id, str(user.get('user_id')), limit)
    return {'results': [_serialize_execution(execution) for execution in executions]}
