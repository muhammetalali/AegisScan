from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.capability_control_plane import control_plane_snapshot, engine_readiness
from ..services.engine_capabilities import capability_for, list_capabilities

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def require_staff(user: dict) -> dict:
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return user


@router.get("/engine-capabilities")
async def engine_capabilities(user: dict = Depends(require_user)):
    return {"engines": list_capabilities()}


@router.get("/engines")
async def engines(user: dict = Depends(require_user)):
    """Compatibility registry for the validation wizard.

    Expose only engines known by the backend capability registry and normalize
    the response shape consumed by the web UI. No static/fallback engines are
    introduced here.
    """
    return [
        {
            "name": item["engine"],
            "display_name": item["engine"],
            "real_executor_registered": item.get("status") == "implemented" and bool(item.get("executor")),
            "status": item.get("status", "unavailable"),
            "executor": item.get("executor"),
            "evidence": bool(item.get("evidence")),
        }
        for item in list_capabilities()
    ]


@router.get("/engine-capabilities/{engine}")
async def engine_capability(engine: str, user: dict = Depends(require_user)):
    return capability_for(engine)


@router.get("/engine-capabilities-control-plane")
async def engine_capability_control_plane(user: dict = Depends(require_user)):
    require_staff(user)
    return await control_plane_snapshot()


@router.get("/engine-capabilities/{engine}/readiness")
async def engine_capability_readiness(engine: str, user: dict = Depends(require_user)):
    require_staff(user)
    return await engine_readiness(engine)
