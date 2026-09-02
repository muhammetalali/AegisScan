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
    if not user:
        raise HTTPException(status_code=401, detail='Invalid token')
    return user


@sync_to_async
def _has_permission(user_id: str, permission: str) -> bool:
    from django_project.users.models import User
    user = User.objects.filter(pk=user_id, is_active=True).first()
    return bool(user and user.has_permission(permission))


def require_permission(permission: str) -> Callable:
    async def dependency(user=Depends(get_current_user)):
        user_id = str(user.get('user_id'))
        if not user_id or not await _has_permission(user_id, permission):
            raise HTTPException(status_code=403, detail=f'Permission required: {permission}')
        return user
    return dependency
