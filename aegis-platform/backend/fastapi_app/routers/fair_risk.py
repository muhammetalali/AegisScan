from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from enterprise.fair_risk_models import FAIRQuantitativeRiskAnalysis

from ..core.dependencies import get_current_user
from ..services.fair_quantitative_risk import (
    FAIRRiskAuthorizationError,
    FAIRRiskError,
    FAIR_POLICY_VERSION,
    analyze_fair_risk,
)

router = APIRouter()


class ThreePointEstimate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    low: float
    mode: float
    high: float


class FAIRAssumptions(BaseModel):
    model_config = ConfigDict(extra='forbid')
    threat_event_frequency: ThreePointEstimate
    vulnerability: ThreePointEstimate
    primary_loss_magnitude: ThreePointEstimate
    secondary_event_probability: ThreePointEstimate
    secondary_loss_magnitude: ThreePointEstimate


class FAIRAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    risk_correlation_id: str
    assumptions: FAIRAssumptions
    assumption_evidence: dict[str, list[str]]
    iterations: int = Field(default=10000, ge=1000, le=50000)
    seed: int = Field(default=1, ge=0, le=9223372036854775807)
    currency: str = Field(default='USD', min_length=3, max_length=3)


class FAIRAnalysisResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str
    organization_id: str
    project_id: str
    finding_id: str
    risk_correlation_id: str
    predecessor_id: str | None = None
    analysis_version: int
    simulation_iterations: int
    simulation_seed: int
    currency: str
    assumptions: dict[str, Any]
    assumption_evidence: dict[str, Any]
    evidence_snapshot: list[dict[str, Any]]
    assumptions_sha256: str
    evidence_sha256: str
    loss_event_frequency_mean: float
    annual_loss_mean: str
    annual_loss_p50: str
    annual_loss_p95: str
    result_summary: dict[str, Any]
    result_sha256: str
    request_fingerprint: str
    policy_version: str
    created_at: str
    replayed: bool = False


def _serialize(row: FAIRQuantitativeRiskAnalysis, *, replayed: bool = False) -> FAIRAnalysisResponse:
    return FAIRAnalysisResponse(
        id=str(row.id),
        organization_id=str(row.organization_id),
        project_id=str(row.project_id),
        finding_id=str(row.vulnerability_id),
        risk_correlation_id=str(row.risk_correlation_id),
        predecessor_id=str(row.predecessor_id) if row.predecessor_id else None,
        analysis_version=int(row.analysis_version),
        simulation_iterations=int(row.simulation_iterations),
        simulation_seed=int(row.simulation_seed),
        currency=row.currency,
        assumptions=row.assumptions or {},
        assumption_evidence=row.assumption_evidence or {},
        evidence_snapshot=row.evidence_snapshot or [],
        assumptions_sha256=row.assumptions_sha256,
        evidence_sha256=row.evidence_sha256,
        loss_event_frequency_mean=float(row.loss_event_frequency_mean),
        annual_loss_mean=str(row.annual_loss_mean),
        annual_loss_p50=str(row.annual_loss_p50),
        annual_loss_p95=str(row.annual_loss_p95),
        result_summary=row.result_summary or {},
        result_sha256=row.result_sha256,
        request_fingerprint=row.request_fingerprint,
        policy_version=row.policy_version,
        created_at=row.created_at.isoformat(),
        replayed=replayed,
    )


def _project_for_user(project_id: str, user_id: str):
    return (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )


@sync_to_async
def _analyze(project_id: str, user_id: str, request: FAIRAnalysisRequest) -> FAIRAnalysisResponse:
    try:
        result = analyze_fair_risk(
            project_id=project_id,
            risk_correlation_id=request.risk_correlation_id,
            actor_id=user_id,
            assumptions=request.assumptions.model_dump(),
            assumption_evidence=request.assumption_evidence,
            iterations=request.iterations,
            seed=request.seed,
            currency=request.currency,
        )
    except FAIRRiskAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FAIRRiskError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _serialize(result.analysis, replayed=result.replayed)


@sync_to_async
def _list(project_id: str, user_id: str, limit: int) -> list[FAIRAnalysisResponse]:
    project = _project_for_user(project_id, user_id)
    if project is None:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    rows = FAIRQuantitativeRiskAnalysis.objects.filter(project=project).order_by('-created_at', '-id')[:limit]
    return [_serialize(row) for row in rows]


@sync_to_async
def _get(analysis_id: str, user_id: str) -> FAIRAnalysisResponse:
    row = (
        FAIRQuantitativeRiskAnalysis.objects.filter(pk=analysis_id)
        .filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id))
        .distinct()
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail='FAIR analysis not found or inaccessible')
    return _serialize(row)


@router.post('/projects/{project_id}/analyses', response_model=FAIRAnalysisResponse)
async def create_analysis(project_id: str, request: FAIRAnalysisRequest, user=Depends(get_current_user)):
    return await _analyze(project_id, str(user.get('user_id')), request)


@router.get('/projects/{project_id}/analyses', response_model=list[FAIRAnalysisResponse])
async def list_analyses(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    user=Depends(get_current_user),
):
    return await _list(project_id, str(user.get('user_id')), limit)


@router.get('/analyses/{analysis_id}', response_model=FAIRAnalysisResponse)
async def get_analysis(analysis_id: str, user=Depends(get_current_user)):
    return await _get(analysis_id, str(user.get('user_id')))
