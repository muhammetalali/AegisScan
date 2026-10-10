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


def project_access_q(user_id: str, *, relation: str = ""):
    """Return one SQL predicate for company-owner or project-member access.

    The primary owner is verified from the database (active + superuser +
    configured owner email), not from untrusted request claims. The Exists
    subquery avoids additional SQL round trips in paginated list endpoints.
    Employees retain project ownership/membership checks.
    """
    from django.conf import settings
    from django.db.models import Exists, Q
    from django_project.users.models import User

    prefix = f"{relation}__" if relation else ""
    primary_owner = Exists(
        User.objects.filter(
            pk=user_id,
            is_active=True,
            is_superuser=True,
            email__iexact=settings.AEGIS_PRIMARY_OWNER_EMAIL,
        )
    )
    owner_branch = Q(primary_owner)
    if relation:
        # Do not grant owner access to records without a linked project.
        owner_branch &= Q(**{f"{relation}__isnull": False})
    return (
        owner_branch
        | Q(**{f"{prefix}owner_id": user_id})
        | Q(**{f"{prefix}members__id": user_id})
    )


def require_permission(permission: str) -> Callable:
    async def dependency(user=Depends(get_current_user)):
        user_id = str(user.get('user_id'))
        if not user_id or not await _has_permission(user_id, permission):
            raise HTTPException(status_code=403, detail=f'Permission required: {permission}')
        return user
    return dependency
