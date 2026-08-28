from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.capability_control_plane import control_plane_snapshot, engine_readiness, provider_control_plane

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/capabilities/control-plane")
async def control_plane(user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return await control_plane_snapshot()


@router.get("/capabilities/engines/{engine}/readiness")
async def engine_capability_readiness(engine: str, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return await engine_readiness(engine)


@router.get("/capabilities/providers/{provider}")
async def provider_capability_control(provider: str, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    if provider not in {"jira", "servicenow"}:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    return await provider_control_plane(provider)
