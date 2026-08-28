from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.itsm_capability import all_provider_capabilities
from ..services.itsm_configuration import validate_itsm_configuration
from ..services.itsm_provider_health import check_all_providers, check_provider
from ..services.itsm_remediation_resilient import create_case

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


class TicketRequest(BaseModel):
    provider: str | None = Field(default=None, pattern="^(jira|servicenow)$")
    providers: list[str] = Field(default_factory=lambda: ["jira", "servicenow"], min_length=1, max_length=2)
    decision: dict[str, Any]
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    idempotency_key: str = Field(min_length=16, max_length=200)
    owner: str = Field(default="security-engineering", max_length=256)
    approved: bool = False


@router.get("/integrations")
async def integration_status(user: dict[str, Any] = Depends(current_user)):
    states = validate_itsm_configuration()
    return {
        "providers": [
            {
                "id": provider,
                "enabled": state.enabled,
                "valid": state.valid,
                "errors": list(state.errors),
            }
            for provider, state in states.items()
        ]
    }


@router.get("/providers/health")
async def provider_health(user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return await check_all_providers()


@router.get("/providers/{provider}/health")
async def provider_health_one(provider: str, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    if provider not in {"jira", "servicenow"}:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    return await check_provider(provider)


@router.get("/providers/capabilities")
async def provider_capabilities(user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return {"providers": await all_provider_capabilities()}


@router.get("/providers/{provider}/capabilities")
async def provider_capabilities_one(provider: str, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    if provider not in {"jira", "servicenow"}:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    from ..services.itsm_capability import provider_capability
    return await provider_capability(provider)


@router.post("/tickets")
async def create_ticket(body: TicketRequest, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    actor = str(user.get("id") or user.get("username") or "user")
    providers = [body.provider] if body.provider else body.providers
    try:
        return await create_case(
            decision=body.decision,
            owner=body.owner,
            actor=actor,
            idempotency_key=body.idempotency_key,
            providers=providers,
            evidence=body.evidence,
            approved=body.approved,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
