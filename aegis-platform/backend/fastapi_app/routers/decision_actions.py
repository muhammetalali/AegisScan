from __future__ import annotations

from typing import Any
from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.graph_intelligence import analyze_graph
from ..services.autonomous_triage import build_triage
from ..services.security_decision import build_decision_pack
from ..services.decision_action_orchestration import create_action, get_action, list_actions, transition
from ..services.workflow_intelligence import enrich_action, workflow_metrics
from ..services.audit_writer import add_audit_entry
from .assurance_graph import _load_validations

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


async def _decision_by_id(decision_id: str, user_id: str) -> dict[str, Any] | None:
    validations = await _load_validations(user_id)
    correlations = correlate_all(validations)
    graph = analyze_graph(build_assurance_graph(validations, correlations))
    triage = build_triage(graph)
    pack = build_decision_pack(triage)
    return next((item for item in pack.get("decisions", []) if item.get("decisionId") == decision_id), None)


@router.get("/actions")
async def actions(user: dict[str, Any] = Depends(require_user)):
    items = [enrich_action(item) for item in list_actions()]
    return {"items": items, "metrics": workflow_metrics(items)}


@router.get("/actions/overview")
async def actions_overview(user: dict[str, Any] = Depends(require_user)):
    items = [enrich_action(item) for item in list_actions()]
    return {"items": items, "metrics": workflow_metrics(items)}


@router.post("/actions", status_code=201)
async def create_action_endpoint(body: ActionCreate, request: Request, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "user")
    decision = await _decision_by_id(body.decision_id, actor)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    item = create_action(decision, body.owner, body.sla_hours, actor)
    await sync_to_async(add_audit_entry)(
        user=actor,
        action="decision_action.create",
        target=item["actionId"],
        project="—",
        result="success",
        resource_type="decision_action",
        request=request,
    )
    return enrich_action(item)


@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return enrich_action(item)


@router.post("/actions/{action_id}/transition")
async def action_transition(action_id: str, body: ActionTransition, request: Request, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "user")
    try:
        item = transition(action_id, body.state, actor, body.note)
        await sync_to_async(add_audit_entry)(
            user=actor,
            action=f"decision_action.{body.state}",
            target=action_id,
            project="—",
            result="success",
            resource_type="decision_action",
            metadata={"note": body.note or ""},
            request=request,
        )
        return enrich_action(item)
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid action state")
