from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.capability_control_plane import control_plane_snapshot, engine_readiness, provider_control_plane
from ..services.lab_registry import capability_detail, capability_catalog, lab_catalog, lab_detail, lab_readiness, lab_snapshot

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def require_staff(user: dict[str, Any]) -> None:
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")


@router.get("/capabilities/control-plane")
async def control_plane(user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    return await control_plane_snapshot()


@router.get("/capabilities/engines/{engine}/readiness")
async def engine_capability_readiness(engine: str, user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    return await engine_readiness(engine)


@router.get("/capabilities/providers/{provider}")
async def provider_capability_control(provider: str, user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    if provider not in {"jira", "servicenow"}:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    return await provider_control_plane(provider)


@router.get("/capabilities/labs")
async def labs_capabilities(user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    return {"labs": lab_catalog(), "capabilities": capability_catalog()}


@router.get("/capabilities/labs/snapshot")
async def labs_snapshot(user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    return lab_snapshot()


@router.get("/capabilities/labs/{lab_id}")
async def lab_capability(lab_id: str, user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    lab = lab_detail(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found")
    return lab


@router.get("/capabilities/labs/{lab_id}/readiness")
async def lab_capability_readiness(lab_id: str, user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    readiness = lab_readiness(lab_id)
    if readiness["readiness"] == "not_found":
        raise HTTPException(status_code=404, detail="Lab not found")
    return readiness


@router.get("/capabilities/lab-tools/{capability_id:path}")
async def lab_tool_capability(capability_id: str, user: dict[str, Any] = Depends(current_user)):
    require_staff(user)
    capability = capability_detail(capability_id)
    if not capability:
        raise HTTPException(status_code=404, detail="Lab capability not found")
    return capability
