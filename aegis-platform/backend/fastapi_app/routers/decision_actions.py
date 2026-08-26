from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.graph_intelligence import analyze_graph
from ..services.autonomous_triage import build_triage
from ..services.security_decision import build_decision_pack
from ..services.decision_action_orchestration import create_action, get_action, list_actions, transition

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

class ActionCreate(BaseModel):
    decision_id: str
    owner: str = Field(min_length=1, max_length=256)
    sla_hours: int = Field(default=24, ge=1, le=8760)

class ActionTransition(BaseModel):
    state: str
    note: str | None = Field(default=None, max_length=2000)


def _decision_by_id(decision_id: str) -> dict[str, Any] | None:
    from .validations import _store
    correlations = correlate_all(_store)
    graph = build_assurance_graph(_store, correlations)
    intelligence = analyze_graph(graph)
    triage = build_triage(intelligence)
    pack = build_decision_pack(triage)
    return next((item for item in pack.get("decisions", []) if item.get("decisionId") == decision_id), None)

@router.get("/actions")
async def actions(user: dict[str, Any] = Depends(require_user)):
    return {"items": list_actions()}

@router.post("/actions", status_code=201)
async def create_action_endpoint(body: ActionCreate, user: dict[str, Any] = Depends(require_user)):
    decision = _decision_by_id(body.decision_id)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    actor = str(user.get("id") or user.get("username") or "user")
    item = create_action(decision, body.owner, body.sla_hours, actor)
    try:
        from .audit import add_audit_entry
        add_audit_entry(user=actor, action="decision_action.create", target=item["actionId"], project="—", result="success")
    except Exception:
        pass
    return item

@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return item

@router.post("/actions/{action_id}/transition")
async def action_transition(action_id: str, body: ActionTransition, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    try:
        item = transition(action_id, body.state, actor, body.note)
        try:
            from .audit import add_audit_entry
            add_audit_entry(user=actor, action=f"decision_action.{body.state}", target=action_id, project="—", result="success")
        except Exception:
            pass
        return item
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid action state")
