from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.decision_action_orchestration import _decision_by_id if False else None
from ..services.remediation_lifecycle import create_action_and_ticket, get_lifecycle, transition_with_ticket, validate_and_verify

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

class TicketStartRequest(BaseModel):
    decision_id: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=256)
    sla_hours: int = Field(default=24, ge=1, le=8760)
    provider: str = Field(pattern="^(jira|servicenow)$")
    evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=500)

class TransitionRequest(BaseModel):
    state: str
    note: str | None = Field(default=None, max_length=2000)

class VerifyRequest(BaseModel):
    candidate: dict[str, Any]
    tools: list[str] = Field(default_factory=list, max_length=5)
    timeout: int = Field(default=180, ge=1, le=900)


def _find_decision(decision_id: str) -> dict[str, Any] | None:
    from .validations import _store
    from ..services.assurance_correlation import correlate_all
    from ..services.assurance_graph_aggregator import build_assurance_graph
    from ..services.graph_intelligence import analyze_graph
    from ..services.autonomous_triage import build_triage
    from ..services.security_decision import build_decision_pack
    correlations = correlate_all(_store)
    graph = build_assurance_graph(_store, correlations)
    intelligence = analyze_graph(graph)
    triage = build_triage(intelligence)
    pack = build_decision_pack(triage)
    return next((item for item in pack.get("decisions", []) if item.get("decisionId") == decision_id), None)

@router.post("/remediation/start", status_code=201)
async def start_remediation(body: TicketStartRequest, user: dict[str, Any] = Depends(require_user)):
    decision = _find_decision(body.decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    actor = str(user.get("id") or user.get("username") or "user")
    result = await create_action_and_ticket(decision=decision, owner=body.owner, sla_hours=body.sla_hours, actor=actor, provider=body.provider, evidence=body.evidence)
    if result["ticket"].get("status") != "created":
        raise HTTPException(status_code=503, detail={"message": "Remediation action created but external ticket was not created", **result})
    return result

@router.get("/remediation/{action_id}")
async def remediation_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    lifecycle = get_lifecycle(action_id)
    if lifecycle is None:
        raise HTTPException(status_code=404, detail="Remediation lifecycle not found")
    return lifecycle

@router.post("/remediation/{action_id}/transition")
async def remediation_transition(action_id: str, body: TransitionRequest, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        return await transition_with_ticket(action_id, body.state, actor, body.note)
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.post("/remediation/{action_id}/verify")
async def remediation_verify(action_id: str, body: VerifyRequest, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        return await validate_and_verify(action_id, actor, candidate=body.candidate, tools=body.tools or None, timeout=body.timeout)
    except KeyError:
        raise HTTPException(status_code=404, detail="Remediation lifecycle not found")
    except (PermissionError, FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
