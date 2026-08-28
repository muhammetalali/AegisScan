from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.active_surface_scanner import ActiveSurfaceScanner, ScanAuthorizationError
from ..services.attack_surface_profiler import AttackSurfaceProfiler

router = APIRouter()
security = HTTPBearer(auto_error=True)
scanner = ActiveSurfaceScanner()
profiler = AttackSurfaceProfiler()


class ActiveScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=200)
    provider: str = Field(default="nmap", pattern="^(nmap|masscan)$")


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/attack-surface/providers")
async def providers(user: dict = Depends(require_user)):
    return {
        "providers": [
            {"id": "nmap", "mode": "active", "enabled": scanner.enabled, "installed": scanner.enabled and scanner.allowed_networks != ()},
            {"id": "masscan", "mode": "active", "enabled": scanner.enabled, "installed": scanner.enabled and scanner.allowed_networks != ()},
        ],
        "scope_configured": bool(scanner.allowed_networks),
    }


@router.post("/attack-surface/scan")
async def active_scan(body: ActiveScanRequest, user: dict = Depends(require_user)):
    try:
        result = await scanner.scan(body.target, body.provider)  # type: ignore[arg-type]
    except ScanAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    normalized = profiler.normalize(result.observations)
    return {
        "provider": result.provider,
        "target": result.target,
        "count": len(normalized),
        "observations": normalized,
        "mode": "active",
    }
