from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from django_project.security_sessions import services as session_service

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.graph_intelligence import analyze_graph
from ..services.autonomous_triage import build_triage
from ..services.security_decision import build_decision_pack
from ..services.decision_action_orchestration import create_action, get_action, list_actions, transition
from ..services.workflow_intelligence import enrich_action, workflow_metrics

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
    session_id: UUID | None = None


class ActionTransition(BaseModel):
    state: str
    note: str | None = Field(default=None, max_length=2000)
    session_id: UUID | None = None


def _decision_by_id(decision_id: str) -> dict[str, Any] | None:
    from .validations import _store
    correlations = correlate_all(_store)
    graph = build_assurance_graph(_store, correlations)
    intelligence = analyze_graph(graph)
    triage = build_triage(intelligence)
    pack = build_decision_pack(triage)
    return next((item for item in pack.get("decisions", []) if item.get("decisionId") == decision_id), None)


async def _record_session_event(session_id: UUID | None, user: dict[str, Any], *, event_type: str, action: str, data: dict[str, Any]) -> None:
    if session_id is None:
        return
    await run_in_threadpool(
        session_service.append_evidence,
        session_id=session_id,
        user_id=user.get("id"),
        event_type=event_type,
        capability="remediation_execute",
        action=action,
        status="success",
        data=data,
    )


@router.get("/actions")
async def actions(user: dict[str, Any] = Depends(require_user)):
    items = [enrich_action(item) for item in list_actions()]
    return {"items": items, "metrics": workflow_metrics(items)}


@router.get("/actions/overview")
async def actions_overview(user: dict[str, Any] = Depends(require_user)):
    items = [enrich_action(item) for item in list_actions()]
    return {"items": items, "metrics": workflow_metrics(items)}


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
    await _record_session_event(body.session_id, user, event_type="aada.action.created", action="decision_action.create", data={"action_id": item["actionId"], "decision_id": body.decision_id, "owner": body.owner, "sla_hours": body.sla_hours})
    enriched = enrich_action(item)
    if body.session_id is not None:
        enriched["session_id"] = str(body.session_id)
    return enriched


@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return enrich_action(item)


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
        await _record_session_event(body.session_id, user, event_type="aada.action.transitioned", action=f"decision_action.{body.state}", data={"action_id": action_id, "state": body.state, "note": body.note})
        enriched = enrich_action(item)
        if body.session_id is not None:
            enriched["session_id"] = str(body.session_id)
        return enriched
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid action state")
