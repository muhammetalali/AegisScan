from __future__ import annotations

from typing import Any
from asgiref.sync import sync_to_async
from django.db.models import Q
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
from enterprise.models import RiskCorrelationSnapshot
from enterprise.services import ensure_project_tenant
from django_project.evidence.models import ValidationRun
from django_project.projects.models import Project

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
    verification_validation_id: str | None = None


async def _decision_by_id(decision_id: str, user_id: str) -> dict[str, Any] | None:
    validations = await _load_validations(user_id)
    correlations = correlate_all(validations)
    graph = analyze_graph(build_assurance_graph(validations, correlations))
    triage = build_triage(graph)
    pack = build_decision_pack(triage)
    return next((item for item in pack.get("decisions", []) if item.get("decisionId") == decision_id), None)


def _resolve_action_scope(decision: dict[str, Any], user_id: str):
    validation_id = decision.get("validationId")
    project_id = decision.get("projectId")
    if not validation_id or not project_id:
        raise ValueError("Decision has no verified validation/project lineage")
    validation = ValidationRun.objects.select_related(
        'finding__project','authorization_decision__asset__project',
    ).filter(pk=validation_id,user_id=user_id).first()
    if validation is None:
        raise PermissionError("Validation is outside the authenticated scope")
    project = Project.objects.filter(pk=project_id).filter(
        Q(owner_id=user_id) | Q(members__id=user_id),
    ).distinct().first()
    if project is None:
        raise PermissionError("Project is outside the authenticated scope")
    validation_project_id = validation.finding.project_id if validation.finding_id else (
        validation.authorization_decision.asset.project_id if validation.authorization_decision_id else None
    )
    if str(validation_project_id) != str(project.id):
        raise PermissionError("Decision lineage does not match the validation project")
    risk_correlation = None
    risk_correlation_id = decision.get("riskCorrelationId")
    if risk_correlation_id:
        risk_correlation = RiskCorrelationSnapshot.objects.filter(pk=risk_correlation_id, project=project).first()
        if risk_correlation is None:
            raise PermissionError("Risk-correlation snapshot is outside the authenticated scope")
        if not validation.finding_id or str(risk_correlation.vulnerability_id) != str(validation.finding_id):
            raise PermissionError("Risk-correlation lineage does not match the validation finding")
        if str(decision.get("riskCorrelationSha256") or "") != str(risk_correlation.correlation_sha256):
            raise ValueError("Decision risk-correlation SHA256 is stale or invalid")
    organization = ensure_project_tenant(project,user_id)
    return organization,project,validation,risk_correlation


@router.get("/actions")
async def actions(user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    stored_actions = await sync_to_async(list_actions)(actor)
    items = [enrich_action(item) for item in stored_actions]
    return {"items": items, "metrics": workflow_metrics(items)}


@router.get("/actions/overview")
async def actions_overview(user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    stored_actions = await sync_to_async(list_actions)(actor)
    items = [enrich_action(item) for item in stored_actions]
    return {"items": items, "metrics": workflow_metrics(items)}


@router.post("/actions", status_code=201)
async def create_action_endpoint(body: ActionCreate, request: Request, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    decision = await _decision_by_id(body.decision_id, actor)
    if decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    if decision.get("actionable") is False:
        raise HTTPException(status_code=409, detail=str(decision.get("actionabilityReason") or "Decision is not actionable"))
    try:
        organization,project,validation,risk_correlation = await sync_to_async(_resolve_action_scope)(decision,actor)
        item = await sync_to_async(create_action)(
            decision,body.owner,body.sla_hours,actor,
            organization=organization,project=project,validation=validation,risk_correlation=risk_correlation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except PermissionError:
        raise HTTPException(status_code=404, detail="Decision scope not found")
    await sync_to_async(add_audit_entry)(
        user=actor, action="decision_action.create", target=item["actionId"], project=str(project.id),
        result="success", resource_type="decision_action",
        metadata={
            "organization_id":str(organization.id), "validation_id":str(validation.id),
            "risk_correlation_id":str(risk_correlation.id) if risk_correlation else None,
            "risk_correlation_sha256":risk_correlation.correlation_sha256 if risk_correlation else None,
        }, request=request,
    )
    return enrich_action(item)


@router.get("/actions/{action_id}")
async def action_detail(action_id: str, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    item = await sync_to_async(get_action)(action_id, actor)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return enrich_action(item)


@router.post("/actions/{action_id}/transition")
async def action_transition(action_id: str, body: ActionTransition, request: Request, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        item = await sync_to_async(transition)(
            action_id, body.state, actor, body.note, body.verification_validation_id,
        )
        await sync_to_async(add_audit_entry)(
            user=actor, action=f"decision_action.{body.state}", target=action_id,
            project=str(item.get("projectId") or "—"), result="success", resource_type="decision_action",
            metadata={
                "note": body.note or "",
                "verification_validation_id": body.verification_validation_id,
                "verification_evidence_ids": item.get("verificationEvidenceIds", []),
                "verification_evidence_sha256": item.get("verificationEvidenceSha256", []),
                "risk_correlation_id": item.get("riskCorrelationId"),
                "risk_correlation_sha256": item.get("riskCorrelationSha256"),
            }, request=request,
        )
        return enrich_action(item)
    except KeyError:
        raise HTTPException(status_code=404, detail="Action not found")
    except ValueError as exc:
        raise HTTPException(status_code=409 if body.state == "verified" else 400, detail=str(exc))
