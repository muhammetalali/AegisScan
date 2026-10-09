from __future__ import annotations

from typing import Callable

from asgiref.sync import sync_to_async
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .security import verify_token

bearer = HTTPBearer(auto_error=False)


async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials if credentials else request.cookies.get('aegis_access')
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    user = await verify_token(token)
    if not user or not await _is_active_user(str(user.get('user_id') or '')):
        raise HTTPException(status_code=401, detail='Invalid token')
    return user


@sync_to_async
def _is_active_user(user_id: str) -> bool:
    from django.core.exceptions import ValidationError
    from django_project.users.models import User
    if not user_id:
        return False
    try:
        return User.objects.filter(pk=user_id, is_active=True).exists()
    except (TypeError, ValueError, ValidationError):
        return False


@sync_to_async
def _has_permission(user_id: str, permission: str) -> bool:
    from django_project.users.models import User
    user = User.objects.filter(pk=user_id, is_active=True).first()
    return bool(user and user.has_permission(permission))


def is_primary_company_owner(user_id: str) -> bool:
    """Identify the primary owner via the active Django user, not client claims."""
    from django_project.users.models import User

    actor = User.objects.filter(pk=user_id, is_active=True).first()
    return bool(actor and actor.is_company_owner)


def accessible_projects_for_user(user_id: str):
    """Single project-access policy for the company owner and regular staff."""
    from django.db.models import Q
    from django_project.projects.models import Project

    projects = Project.objects.all()
    if is_primary_company_owner(user_id):
        return projects
    return projects.filter(Q(owner_id=user_id) | Q(members__id=user_id)).distinct()


def require_permission(permission: str) -> Callable:
    async def dependency(user=Depends(get_current_user)):
        user_id = str(user.get('user_id'))
        if not user_id or not await _has_permission(user_id, permission):
            raise HTTPException(status_code=403, detail=f'Permission required: {permission}')
        return user
    return dependency
