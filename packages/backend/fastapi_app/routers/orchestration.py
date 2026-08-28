from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
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
    import os
    return {"providers": [
        {"id": "jira", "configured": bool(os.getenv("JIRA_BASE_URL") and os.getenv("JIRA_API_TOKEN") and os.getenv("JIRA_USER_EMAIL") and os.getenv("JIRA_PROJECT_KEY"))},
        {"id": "servicenow", "configured": bool(os.getenv("SERVICENOW_BASE_URL") and (os.getenv("SERVICENOW_API_TOKEN") or (os.getenv("SERVICENOW_USERNAME") and os.getenv("SERVICENOW_PASSWORD"))))},
    ]}

@router.post("/tickets")
async def create_ticket(body: TicketRequest, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    actor = str(user.get("id") or user.get("username") or "user")
    providers = [body.provider] if body.provider else body.providers
    try:
        return await create_case(decision=body.decision, owner=body.owner, actor=actor, idempotency_key=body.idempotency_key, providers=providers, evidence=body.evidence, approved=body.approved)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
