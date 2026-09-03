from __future__ import annotations

from typing import Optional
from uuid import UUID, uuid4

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, Query

from django_project.audit.models import AuditLog, SecurityEvent
from django_project.users.models import APIKey, LoginAttempt, Team, User, UserRole

from ..core.dependencies import get_current_user

router = APIRouter()

ROLES = [{'id': role.value, 'name': role.label} for role in UserRole]


@sync_to_async
def _audit_logs(limit: int, action: Optional[str], user: Optional[str]):
    qs = AuditLog.objects.select_related('user').order_by('-created_at')
    if action:
        qs = qs.filter(action=action)
    if user:
        qs = qs.filter(user__email=user)
    total = qs.count()
    rows = list(qs[:limit])
    return [
        {
            'id': str(row.id),
            'user': row.user.email if row.user else 'system',
            'action': row.action,
            'project': row.metadata.get('project', row.resource_type) if isinstance(row.metadata, dict) else row.resource_type,
            'target': row.resource_repr or row.resource_id,
            'timestamp': row.created_at.isoformat(),
            'result': row.result,
            'ip': str(row.ip_address),
            'request_id': str(row.request_id),
        }
        for row in rows
    ], total


@sync_to_async
def _users():
    return [
        {
            'id': str(user.id),
            'email': user.email,
            'name': user.get_full_name(),
            'role': user.role,
            'team_ids': [str(team.id) for team in user.teams.filter(is_active=True)],
            'status': 'active' if user.is_active else 'inactive',
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'last_activity': user.last_activity.isoformat() if user.last_activity else None,
        }
        for user in User.objects.all().order_by('email')
    ]


@sync_to_async
def _teams():
    return [
        {
            'id': str(team.id),
            'name': team.name,
            'description': team.description,
            'owner_id': str(team.owner_id),
            'members': team.members.count(),
            'active': team.is_active,
        }
        for team in Team.objects.all().order_by('name')
    ]


@sync_to_async
def _api_keys(user_id: str):
    rows = APIKey.objects.filter(user_id=user_id).select_related('team').order_by('-created_at')
    return [
        {
            'id': str(key.id),
            'name': key.name,
            'prefix': key.key_prefix,
            'permissions': key.permissions or [],
            'team_id': str(key.team_id) if key.team_id else None,
            'created_at': key.created_at.isoformat(),
            'last_used': key.last_used_at.isoformat() if key.last_used_at else None,
            'expires_at': key.expires_at.isoformat() if key.expires_at else None,
            'active': key.is_active,
        }
        for key in rows
    ]


@sync_to_async
def _sessions(user_id: str):
    return [
        {
            'id': str(session.id),
            'user': session.user.email,
            'ip': str(session.ip_address),
            'user_agent': session.user_agent,
            'location': session.location,
            'current': session.is_current,
            'created_at': session.created_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
        }
        for session in User.objects.get(pk=user_id).sessions.all().order_by('-last_activity')
    ]


@sync_to_async
def _login_attempts(limit: int):
    return [
        {
            'id': str(row.id),
            'user': row.email,
            'ip': str(row.ip_address),
            'success': row.success,
            'failure_reason': row.failure_reason,
            'timestamp': row.created_at.isoformat(),
        }
        for row in LoginAttempt.objects.all().order_by('-created_at')[:limit]
    ]


@sync_to_async
def _security_events(limit: int):
    return [
        {
            'id': str(row.id),
            'event_type': row.event_type,
            'severity': row.severity,
            'status': row.status,
            'title': row.title,
            'description': row.description,
            'source_ip': str(row.source_ip) if row.source_ip else None,
            'target_user': row.target_user.email if row.target_user else None,
            'target_resource_type': row.target_resource_type,
            'target_resource_id': row.target_resource_id,
            'created_at': row.created_at.isoformat(),
        }
        for row in SecurityEvent.objects.select_related('target_user').order_by('-created_at')[:limit]
    ]


def _actor_id(current_user: dict) -> str:
    return str(current_user.get('user_id') or current_user.get('id'))


def add_audit_entry(user: str, action: str, target: str, project: str = '—', result: str = 'success', ip: str = '127.0.0.1'):
    actor = User.objects.filter(pk=user).first() or User.objects.filter(email=user).first()
    if actor is None:
        return None
    try:
        action_value = AuditLog.Action(action)
    except ValueError:
        return None
    try:
        result_value = AuditLog.Result(result)
    except ValueError:
        result_value = AuditLog.Result.SUCCESS
    return AuditLog.objects.create(
        user=actor,
        action=action_value,
        result=result_value,
        resource_id=str(target)[:100],
        resource_repr=str(target)[:200],
        metadata={'project': project},
        ip_address=ip,
        request_id=uuid4(),
    )


@router.get('/audit/logs')
async def list_audit_logs(limit: int = Query(20, ge=1, le=100), action: Optional[str] = None, user: Optional[str] = None, current_user=Depends(get_current_user)):
    items, total = await _audit_logs(limit, action, user)
    return {'items': items, 'total': total}


@router.get('/audit/roles')
async def list_roles(current_user=Depends(get_current_user)):
    return {'items': ROLES, 'total': len(ROLES)}


@router.get('/audit/users')
async def list_users(current_user=Depends(get_current_user)):
    items = await _users()
    return {'items': items, 'total': len(items)}


@router.get('/audit/teams')
async def list_teams(current_user=Depends(get_current_user)):
    items = await _teams()
    return {'items': items, 'total': len(items)}


@router.get('/audit/api-keys')
async def list_api_keys(current_user=Depends(get_current_user)):
    items = await _api_keys(_actor_id(current_user))
    return {'items': items, 'total': len(items)}


@router.get('/audit/sessions')
async def list_sessions(current_user=Depends(get_current_user)):
    items = await _sessions(_actor_id(current_user))
    return {'items': items, 'total': len(items)}


@router.get('/audit/login-attempts')
async def list_login_attempts(limit: int = Query(20, ge=1, le=100), current_user=Depends(get_current_user)):
    items = await _login_attempts(limit)
    return {'items': items, 'total': len(items)}


@router.get('/audit/security-events')
async def list_security_events(limit: int = Query(20, ge=1, le=100), current_user=Depends(get_current_user)):
    items = await _security_events(limit)
    return {'items': items, 'total': len(items)}
