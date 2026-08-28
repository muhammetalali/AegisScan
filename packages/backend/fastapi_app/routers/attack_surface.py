from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from django_project.security_sessions import services as session_service

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
    session_id: UUID | None = None


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
    if body.session_id is not None:
        await run_in_threadpool(
            session_service.append_evidence,
            session_id=body.session_id,
            user_id=user.get("id"),
            event_type="scanner.active.started",
            capability="active_validate",
            target=body.target,
            action=f"{body.provider}_scan",
            status="started",
            data={"provider": body.provider, "target": body.target},
        )
    try:
        result = await scanner.scan(body.target, body.provider)  # type: ignore[arg-type]
    except ScanAuthorizationError as exc:
        if body.session_id is not None:
            await run_in_threadpool(
                session_service.append_evidence,
                session_id=body.session_id,
                user_id=user.get("id"),
                event_type="scanner.active.completed",
                capability="active_validate",
                target=body.target,
                action=f"{body.provider}_scan",
                status="blocked",
                data={"error": str(exc)},
            )
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuntimeError as exc:
        if body.session_id is not None:
            await run_in_threadpool(
                session_service.append_evidence,
                session_id=body.session_id,
                user_id=user.get("id"),
                event_type="scanner.active.completed",
                capability="active_validate",
                target=body.target,
                action=f"{body.provider}_scan",
                status="failed",
                data={"error": str(exc)},
            )
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    normalized = profiler.normalize(result.observations)
    if body.session_id is not None:
        await run_in_threadpool(
            session_service.append_evidence,
            session_id=body.session_id,
            user_id=user.get("id"),
            event_type="scanner.active.completed",
            capability="active_validate",
            target=body.target,
            action=f"{body.provider}_scan",
            status="success",
            data={
                "provider": result.provider,
                "target": result.target,
                "count": len(normalized),
                "observations": normalized,
                "mode": "active",
            },
        )
    return {
        "session_id": str(body.session_id) if body.session_id else None,
        "provider": result.provider,
        "target": result.target,
        "count": len(normalized),
        "observations": normalized,
        "mode": "active",
    }
