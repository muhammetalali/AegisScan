from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.ticket_orchestration import TicketOrchestrator

router = APIRouter()
security = HTTPBearer(auto_error=True)
orchestrator = TicketOrchestrator()


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


class TicketRequest(BaseModel):
    provider: str = Field(min_length=3, max_length=32)
    decision: dict[str, Any]
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


@router.get("/integrations")
async def integration_status(user: dict[str, Any] = Depends(current_user)):
    import os
    return {
        "providers": [
            {"id": "jira", "configured": bool(os.getenv("JIRA_BASE_URL") and os.getenv("JIRA_API_TOKEN") and os.getenv("JIRA_USER_EMAIL") and os.getenv("JIRA_PROJECT_KEY"))},
            {"id": "servicenow", "configured": bool(os.getenv("SERVICENOW_BASE_URL") and os.getenv("SERVICENOW_API_TOKEN"))},
        ]
    }


@router.post("/tickets")
async def create_ticket(body: TicketRequest, user: dict[str, Any] = Depends(current_user)):
    if not user.get("is_staff") and not user.get("is_superuser"):
        raise HTTPException(status_code=403, detail="Staff access required")
    try:
        return await orchestrator.create_from_decision(provider=body.provider, decision=body.decision, evidence=body.evidence)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

