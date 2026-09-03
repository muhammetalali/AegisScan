from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from django_project.audit.models import AuditLog
from django_project.users.models import User

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


@sync_to_async
def _record_action_audit(user_id: str, action: AuditLog.Action, target: str, metadata: dict[str, Any]) -> None:
    actor = User.objects.filter(pk=user_id).first()
    if actor is None:
        raise ValueError('Audit actor not found')
    AuditLog.objects.create(
        user=actor,
        action=action,
        result=AuditLog.Result.SUCCESS,
        resource_type='decision_action',
        resource_id=str(target)[:100],
        resource_repr=str(target)[:200],
        metadata=metadata,
        ip_address='127.0.0.1',
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
    actor = str(user.get("user_id") or user.get("id"))
    try:
        item = create_action(decision, body.owner, body.sla_hours, actor)
        await _record_action_audit(actor, AuditLog.Action.DECISION_ACTION_CREATE, item["actionId"], {'decision_id': body.decision_id})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail='Decision action audit persistence failed') from exc
    return enrich_action(item)

@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return enrich_action(item)

@router.post("/actions/{action_id}/transition")
async def action_transition(action_id: str, body: ActionTransition, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id"))
    try:
        item = transition(action_id, body.state, actor, body.note)
        await _record_action_audit(actor, AuditLog.Action.DECISION_ACTION_TRANSITION, action_id, {'state': body.state, 'note': body.note})
        return enrich_action(item)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Action not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail='Decision action audit persistence failed') from exc


@router.post('/remediation/findings/{finding_id}/validated-closure')
async def validated_closure(finding_id: str, body: ValidatedClosureRequest, user: dict[str, Any] = Depends(require_user)):
    actor_id = str(user.get('user_id') or user.get('id'))
    finding = await _finding_access(finding_id, actor_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    try:
        return await sync_to_async(execute_validated_closure)(finding_id, actor_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception:
        logger.exception('Validated remediation failed for finding_id=%s actor_id=%s', finding_id, actor_id)
        raise HTTPException(status_code=500, detail='Validated remediation failed')


@router.get('/remediation/findings/{finding_id}')
async def remediation_history(finding_id: str, user: dict[str, Any] = Depends(require_user)):
    actor_id = str(user.get('user_id') or user.get('id'))
    finding = await _finding_access(finding_id, actor_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    items = await sync_to_async(list_runs_for_finding)(finding_id)
    return {'finding_id': finding_id, 'items': items}


@sync_to_async
def _finding_access(finding_id: str, actor_id: str):
    finding = Vulnerability.objects.select_related('project').filter(pk=finding_id).first()
    if not finding:
        return None
    project = finding.project
    if str(project.owner_id) == str(actor_id) or project.members.filter(pk=actor_id).exists():
        return finding
    return None
