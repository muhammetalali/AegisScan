from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.itsm_remediation_v2 import create_case, get_case, sync_case, transition_case, verify_case

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

class CaseCreate(BaseModel):
    decision: dict[str, Any]
    owner: str = Field(min_length=1, max_length=256)
    idempotency_key: str = Field(min_length=16, max_length=200)
    providers: list[str] = Field(default_factory=lambda: ["jira", "servicenow"], min_length=1, max_length=2)
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    sla_hours: int | None = Field(default=None, ge=1, le=8760)
    approved: bool = False

class TransitionBody(BaseModel):
    state: str = Field(min_length=3, max_length=64)
    note: str | None = Field(default=None, max_length=4000)

class VerifyBody(BaseModel):
    candidate: dict[str, Any]
    tools: list[str] = Field(default_factory=list, max_length=5)
    timeout: int = Field(default=180, ge=10, le=900)

@router.post("/remediation/cases", status_code=201)
async def create_remediation_case(body: CaseCreate, user: dict[str, Any] = Depends(require_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    actor = str(user.get("id") or user.get("username") or "user")
    if not body.decision.get("decisionId"):
        raise HTTPException(status_code=400, detail="decision.decisionId is required")
    try:
        return await create_case(decision=body.decision, owner=body.owner, actor=actor, idempotency_key=body.idempotency_key, providers=body.providers, evidence=body.evidence, sla_hours=body.sla_hours, approved=body.approved)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.get("/remediation/cases/{action_id}")
async def remediation_case(action_id: str, user: dict[str, Any] = Depends(require_user)):
    result = get_case(action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Remediation case not found")
    return result

@router.post("/remediation/cases/{action_id}/sync")
async def remediation_case_sync(action_id: str, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        return await sync_case(action_id, actor)
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation case not found")

@router.post("/remediation/cases/{action_id}/transition")
async def remediation_case_transition(action_id: str, body: TransitionBody, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        return await transition_case(action_id, body.state, actor, body.note)
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation case not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/remediation/cases/{action_id}/verify")
async def remediation_case_verify(action_id: str, body: VerifyBody, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        return await verify_case(action_id, actor, body.candidate, tools=body.tools or None, timeout=body.timeout)
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation case not found")
    except (PermissionError, FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
