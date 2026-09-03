from __future__ import annotations

from typing import Any
import logging

from asgiref.sync import sync_to_async
from django.db import connections
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
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
from ..services.workflow_intelligence import enrich_action, workflow_metrics
from ..services.remediation_loop import execute_validated_closure, list_runs_for_finding

logger = logging.getLogger(__name__)
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


class ValidatedClosureRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


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
    actor = str(user.get("id") or user.get("user_id") or user.get("username") or "user")
    return enrich_action(create_action(decision, body.owner, body.sla_hours, actor))


@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return enrich_action(item)


@router.post("/actions/{action_id}/transition")
async def action_transition(action_id: str, body: ActionTransition, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("user_id") or user.get("username") or "user")
    try:
        return enrich_action(transition(action_id, body.state, actor, body.note))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Action not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid action state") from exc


@sync_to_async
def _finding_access(finding_id: str, actor_id: str):
    finding = Vulnerability.objects.select_related('project').filter(pk=finding_id).first()
    if not finding:
        return None
    project = finding.project
    if str(project.owner_id) == str(actor_id) or project.members.filter(pk=actor_id).exists():
        return finding
    return None


@sync_to_async
def _verified_history_proof(finding_id: str, actor_id: str) -> dict[str, Any]:
    connections.close_all()
    history = (
        VulnerabilityStatusHistory.objects
        .filter(vulnerability_id=finding_id, new_status=Vulnerability.Status.FIXED, changed_by_id=actor_id)
        .order_by('-created_at', '-id')
        .first()
    )
    if history is None:
        raise RuntimeError('Verified closure status history is missing from persistent storage')
    finding = Vulnerability.objects.filter(pk=finding_id).values('status', 'risk_score', 'validation_status').first()
    if not finding or finding['status'] != Vulnerability.Status.FIXED or float(finding['risk_score'] or 0) != 0.0:
        raise RuntimeError('Verified closure finding state is inconsistent with persistent proof')
    return {'status_history_id': str(history.id), 'finding_status': finding['status'], 'risk_score': float(finding['risk_score'] or 0), 'validation_status': finding['validation_status']}


@router.post('/remediation/findings/{finding_id}/validated-closure')
async def validated_closure(finding_id: str, body: ValidatedClosureRequest, user: dict[str, Any] = Depends(require_user)):
    actor_id = str(user.get('user_id') or user.get('id'))
    finding = await _finding_access(finding_id, actor_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    try:
        payload = await sync_to_async(execute_validated_closure)(finding_id, actor_id, body.reason)
        if payload.get('state') == 'verified':
            proof = await _verified_history_proof(finding_id, actor_id)
            payload = {**payload, **proof}
        return payload
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
