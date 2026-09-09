from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db import transaction
from django.utils import timezone as django_timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user, require_permission
from django_project.audit.models import AuditLog, SecurityEvent
from django_project.audit.services import append_audit
from django_project.users.models import APIKey, LoginAttempt, Permission, Team, User, UserRole, UserSession

router = APIRouter()


EventStatus = Literal['new', 'investigating', 'resolved', 'false_positive']
EventSeverity = Literal['low', 'medium', 'high', 'critical']


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(extra='forbid')

    id: UUID
    event_type: str
    severity: EventSeverity
    status: EventStatus
    title: str
    description: str
    source_ip: Optional[str]
    target_user_id: Optional[str]
    target_user_email: Optional[str]
    indicators: list[str]
    raw_data: dict[str, Any]
    assigned_to_id: Optional[str]
    resolved_by_id: Optional[str]
    resolved_at: Optional[datetime]
    resolution_notes: str
    created_at: datetime
    updated_at: datetime


class SecurityEventListOut(BaseModel):
    model_config = ConfigDict(extra='forbid')

    items: list[SecurityEventOut]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class SecurityEventTransition(BaseModel):
    model_config = ConfigDict(extra='forbid')

    status: Literal['investigating', 'resolved', 'false_positive']
    resolution_notes: str = Field(default='', max_length=10000)


def _security_event_queryset(user_id: str):
    current = User.objects.filter(pk=user_id, is_active=True).first()
    if current is None:
        raise HTTPException(status_code=401, detail='User not found')
    qs = SecurityEvent.objects.select_related('target_user', 'assigned_to', 'resolved_by')
    if current.is_staff:
        return qs
    return qs.filter(
        notifications__organization__memberships__user=current,
        notifications__organization__memberships__is_active=True,
        notifications__organization__is_active=True,
    ).distinct()


def _security_event_json(item: SecurityEvent) -> dict:
    return {
        'id': str(item.id), 'event_type': item.event_type, 'severity': item.severity, 'status': item.status,
        'title': item.title, 'description': item.description,
        'source_ip': str(item.source_ip) if item.source_ip else None,
        'target_user_id': str(item.target_user_id) if item.target_user_id else None,
        'target_user_email': item.target_user.email if item.target_user else None,
        'indicators': item.indicators or [], 'raw_data': item.raw_data or {},
        'assigned_to_id': str(item.assigned_to_id) if item.assigned_to_id else None,
        'resolved_by_id': str(item.resolved_by_id) if item.resolved_by_id else None,
        'resolved_at': item.resolved_at.astimezone(timezone.utc).isoformat() if item.resolved_at else None,
        'resolution_notes': item.resolution_notes,
        'created_at': item.created_at.astimezone(timezone.utc).isoformat(),
        'updated_at': item.updated_at.astimezone(timezone.utc).isoformat(),
    }


@sync_to_async
def _security_events(user_id: str, limit: int, offset: int, status: Optional[str], severity: Optional[str]):
    qs = _security_event_queryset(user_id).order_by('-created_at')
    if status:
        if status not in set(SecurityEvent.Status.values):
            raise HTTPException(status_code=422, detail='Unsupported security event status')
        qs = qs.filter(status=status)
    if severity:
        if severity not in set(SecurityEvent.Severity.values):
            raise HTTPException(status_code=422, detail='Unsupported security event severity')
        qs = qs.filter(severity=severity)
    total = qs.count()
    return {'items': [_security_event_json(item) for item in qs[offset:offset + limit]], 'total': total, 'limit': limit, 'offset': offset}


@sync_to_async
def _security_event(user_id: str, event_id: str):
    item = _security_event_queryset(user_id).filter(pk=event_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail='Security event not found')
    return _security_event_json(item)


@sync_to_async
def _transition_security_event(
    user_id: str, event_id: str, transition: SecurityEventTransition,
    ip_address: str = '0.0.0.0', user_agent: str = '', request_id: Optional[UUID] = None,
):
    actor = User.objects.filter(pk=user_id, is_active=True).first()
    if actor is None:
        raise HTTPException(status_code=401, detail='User not found')
    with transaction.atomic():
        item = SecurityEvent.objects.select_for_update().filter(pk=event_id).first()
        if item is None:
            raise HTTPException(status_code=404, detail='Security event not found')
        has_tenant_access = actor.is_staff or item.notifications.filter(
            organization__memberships__user=actor,
            organization__memberships__is_active=True,
            organization__is_active=True,
        ).exists()
        if not has_tenant_access:
            raise HTTPException(status_code=404, detail='Security event not found')
        allowed = {
            SecurityEvent.Status.NEW: {SecurityEvent.Status.INVESTIGATING, SecurityEvent.Status.FALSE_POSITIVE},
            SecurityEvent.Status.INVESTIGATING: {SecurityEvent.Status.RESOLVED, SecurityEvent.Status.FALSE_POSITIVE},
            SecurityEvent.Status.RESOLVED: set(),
            SecurityEvent.Status.FALSE_POSITIVE: set(),
        }
        next_status = transition.status
        if next_status not in allowed[item.status]:
            raise HTTPException(status_code=409, detail=f'Invalid security event transition: {item.status} -> {next_status}')
        notes = transition.resolution_notes.strip()
        terminal = next_status in {SecurityEvent.Status.RESOLVED, SecurityEvent.Status.FALSE_POSITIVE}
        if terminal and not notes:
            raise HTTPException(status_code=422, detail='Resolution notes are required for a terminal security event state')
        previous_status = item.status
        item.status = next_status
        update_fields = ['status', 'updated_at']
        if next_status == SecurityEvent.Status.INVESTIGATING:
            item.assigned_to = actor
            update_fields.append('assigned_to')
        if terminal:
            item.resolved_by = actor
            item.resolved_at = django_timezone.now()
            item.resolution_notes = notes
            update_fields.extend(['resolved_by', 'resolved_at', 'resolution_notes'])
        item.save(update_fields=update_fields)
        organization_ids = list(item.notifications.values_list('organization_id', flat=True).distinct())
        append_audit(
            user=actor, action=AuditLog.Action.SECURITY_EVENT_STATUS_CHANGE, result=AuditLog.Result.SUCCESS,
            resource_type='security_event', resource_id=str(item.id), resource_repr=item.title,
            changes={'status': {'from': previous_status, 'to': next_status}},
            metadata={'organization_ids': [str(value) for value in organization_ids], 'resolution_notes_recorded': bool(notes)},
            ip_address=ip_address, user_agent=user_agent[:5000],
            request_id=request_id or AuditLog._meta.get_field('request_id').default(),
        )
        return _security_event_json(item)


@sync_to_async
def _audit_logs(user_id: str, limit: int, action: Optional[str], actor: Optional[str]):
    current = User.objects.filter(pk=user_id).first()
    if not current:
        raise HTTPException(status_code=401, detail='User not found')
    qs = AuditLog.objects.select_related('user').order_by('-created_at')
    if not current.is_staff:
        qs = qs.filter(user_id=user_id)
    if actor:
        qs = qs.filter(user_id=actor)
    if action:
        qs = qs.filter(action=action)
    return [
        {'id': str(item.id), 'user': item.user.email if item.user else None, 'action': item.action, 'result': item.result,
         'resource_type': item.resource_type, 'resource_id': item.resource_id, 'resource_repr': item.resource_repr,
         'changes': item.changes, 'metadata': item.metadata, 'ip': item.ip_address, 'user_agent': item.user_agent,
         'session_id': item.session_id, 'request_id': str(item.request_id), 'error_message': item.error_message,
         'duration_ms': item.duration_ms, 'timestamp': item.created_at.astimezone(timezone.utc).isoformat()}
        for item in qs[:limit]
    ]


@sync_to_async
def _users(user_id: str):
    current = User.objects.get(pk=user_id)
    qs = User.objects.order_by('email')
    if not current.is_staff:
        qs = qs.filter(pk=current.pk)
    return [{'id': str(item.id), 'email': item.email, 'name': item.get_full_name(), 'role': item.role,
             'status': 'active' if item.is_active else 'inactive', 'last_login': item.last_login.isoformat() if item.last_login else None}
            for item in qs]


@sync_to_async
def _teams(user_id: str):
    current = User.objects.get(pk=user_id)
    qs = Team.objects.prefetch_related('members').order_by('name')
    if not current.is_staff:
        qs = qs.filter(members=current)
    return [{'id': str(team.id), 'name': team.name, 'description': team.description, 'members': team.members.count(),
             'owner_id': str(team.owner_id), 'is_active': team.is_active} for team in qs]


@sync_to_async
def _api_keys(user_id: str):
    current = User.objects.get(pk=user_id)
    qs = APIKey.objects.order_by('-created_at')
    if not current.is_staff:
        qs = qs.filter(user=current)
    return [{'id': str(item.id), 'name': item.name, 'prefix': item.key_prefix, 'permissions': item.permissions,
             'created_at': item.created_at.astimezone(timezone.utc).isoformat(),
             'last_used': item.last_used_at.astimezone(timezone.utc).isoformat() if item.last_used_at else None,
             'expires_at': item.expires_at.astimezone(timezone.utc).isoformat() if item.expires_at else None,
             'is_active': item.is_active, 'user_id': str(item.user_id), 'team_id': str(item.team_id) if item.team_id else None}
            for item in qs]


@sync_to_async
def _sessions(user_id: str):
    current = User.objects.get(pk=user_id)
    qs = UserSession.objects.select_related('user').order_by('-last_activity')
    if not current.is_staff:
        qs = qs.filter(user=current)
    return [{'id': str(item.id), 'user': item.user.email, 'ip': item.ip_address, 'user_agent': item.user_agent,
             'location': item.location, 'is_current': item.is_current,
             'created_at': item.created_at.astimezone(timezone.utc).isoformat(),
             'expires_at': item.expires_at.astimezone(timezone.utc).isoformat(),
             'last_activity': item.last_activity.astimezone(timezone.utc).isoformat()} for item in qs]


@sync_to_async
def _login_attempts(user_id: str, limit: int):
    current = User.objects.get(pk=user_id)
    qs = LoginAttempt.objects.order_by('-created_at')
    if not current.is_staff:
        qs = qs.filter(email=current.email)
    return [{'id': str(item.id), 'email': item.email, 'ip': item.ip_address, 'user_agent': item.user_agent,
             'success': item.success, 'failure_reason': item.failure_reason,
             'timestamp': item.created_at.astimezone(timezone.utc).isoformat()} for item in qs[:limit]]


async def _require_audit(user=Depends(get_current_user)):
    user_id = str(user.get('user_id'))
    if not user_id:
        raise HTTPException(status_code=401, detail='Invalid token subject')
    allowed = await sync_to_async(lambda: User.objects.filter(pk=user_id, is_active=True).first())()
    if not allowed or not allowed.has_permission(Permission.AUDIT_READ):
        raise HTTPException(status_code=403, detail=f'Permission required: {Permission.AUDIT_READ}')
    return user


@router.get('/audit/logs')
async def list_audit_logs(limit: int = Query(20, ge=1, le=100), action: Optional[str] = None, user: Optional[str] = None, current_user=Depends(_require_audit)):
    return {'items': await _audit_logs(str(current_user.get('user_id')), limit, action, user), 'limit': limit}


@router.get('/audit/roles')
async def list_roles(current_user=Depends(_require_audit)):
    return {'items': [{'id': value, 'name': label} for value, label in UserRole.choices]}


@router.get('/audit/users')
async def list_users(current_user=Depends(_require_audit)):
    return {'items': await _users(str(current_user.get('user_id')))}


@router.get('/audit/teams')
async def list_teams(current_user=Depends(_require_audit)):
    return {'items': await _teams(str(current_user.get('user_id')))}


@router.get('/audit/api-keys')
async def list_api_keys(current_user=Depends(_require_audit)):
    return {'items': await _api_keys(str(current_user.get('user_id')))}


@router.get('/audit/sessions')
async def list_sessions(current_user=Depends(_require_audit)):
    return {'items': await _sessions(str(current_user.get('user_id')))}


@router.get('/audit/login-attempts')
async def list_login_attempts(limit: int = Query(20, ge=1, le=100), current_user=Depends(_require_audit)):
    return {'items': await _login_attempts(str(current_user.get('user_id')), limit)}


@router.get('/security-events', response_model=SecurityEventListOut)
async def list_security_events(
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    status: Optional[str] = None, severity: Optional[str] = None,
    current_user=Depends(require_permission(Permission.SECURITY_EVENT_READ)),
):
    return await _security_events(str(current_user.get('user_id')), limit, offset, status, severity)


@router.get('/security-events/{event_id}', response_model=SecurityEventOut)
async def get_security_event(event_id: str, current_user=Depends(require_permission(Permission.SECURITY_EVENT_READ))):
    return await _security_event(str(current_user.get('user_id')), event_id)


@router.post('/security-events/{event_id}/transition', response_model=SecurityEventOut)
async def transition_security_event(
    event_id: str, transition: SecurityEventTransition, request: Request,
    current_user=Depends(require_permission(Permission.SECURITY_EVENT_RESPOND)),
):
    raw_request_id = request.headers.get('x-request-id', '')
    try:
        request_id = UUID(raw_request_id) if raw_request_id else None
    except ValueError:
        request_id = None
    client_ip = request.client.host if request.client else '0.0.0.0'
    try:
        ipaddress.ip_address(client_ip)
    except ValueError:
        client_ip = '0.0.0.0'
    return await _transition_security_event(
        str(current_user.get('user_id')), event_id, transition,
        client_ip, request.headers.get('user-agent', ''), request_id,
    )
