from __future__ import annotations

from datetime import timezone
from typing import Optional

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query

from ..core.dependencies import get_current_user, require_permission
from django_project.audit.models import AuditLog
from django_project.users.models import APIKey, LoginAttempt, Permission, Team, User, UserRole, UserSession

router = APIRouter()


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
