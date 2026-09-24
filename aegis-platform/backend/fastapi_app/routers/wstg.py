from __future__ import annotations

from datetime import datetime
from typing import Literal

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project

from ..core.dependencies import get_current_user
from ..services.wstg_reporting import build_wstg_project_coverage
from ..services.wstg_completion_attestation import WSTGAttestationError, create_wstg_methodology_attestation

router = APIRouter()


class ContractModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class WSTGGroupCoverage(ContractModel):
    total: int = Field(ge=0)
    observed: int = Field(ge=0)
    observation_coverage_percent: float = Field(ge=0, le=100)


class WSTGCoverageSummary(ContractModel):
    total_tests: Literal[97]
    observed_tests: int = Field(ge=0, le=97)
    completion_claim_supported_tests: Literal[97]
    methodology_completed_tests: int = Field(ge=0, le=97)
    observation_coverage_percent: float = Field(ge=0, le=100)
    auto_assisted_total: Literal[70]
    auto_assisted_observed: int = Field(ge=0, le=70)
    auto_assisted_observation_coverage_percent: float = Field(ge=0, le=100)
    trusted_evidence_records: int = Field(ge=0)
    trusted_finding_records: int = Field(ge=0)
    rejected_lineage_records: int = Field(ge=0)
    states: dict[str, int]


class WSTGTestCoverage(ContractModel):
    wstg_id: str
    category: str
    title: str
    classification: Literal['AUTO_EXISTING', 'ASSISTED_EXISTING', 'MANUAL_GOVERNED', 'GAP_NATIVE_SMALL', 'CONDITIONAL_NA']
    state: Literal['observed', 'not_observed', 'manual_required', 'blocked_native_gap', 'inconclusive']
    has_observation: bool
    evidence_records: int = Field(ge=0)
    finding_records: int = Field(ge=0)
    capability_ids: list[str]
    latest_observed_at: str | None
    completion_claim_supported: Literal[True]
    completion_claim_allowed: bool
    methodology_completed: bool
    completion_attestation_id: str | None


class WSTGProjectCoverage(ContractModel):
    contract_version: Literal['1.1']
    methodology: Literal['WSTG']
    methodology_version: Literal['4.2']
    source: Literal['postgresql']
    project_id: str
    project_name: str
    scope_scan_id: str | None
    claim_policy: Literal['governed-methodology-completion']
    completion_claim_allowed: bool
    finding_state_authority: Literal['governed-finding-confirmation']
    summary: WSTGCoverageSummary
    category_summary: dict[str, WSTGGroupCoverage]
    classification_summary: dict[str, WSTGGroupCoverage]
    tests: list[WSTGTestCoverage] = Field(min_length=97, max_length=97)


class WSTGAttestationCreate(ContractModel):
    wstg_id: str
    evidence_ids: list[str] = Field(min_length=1, max_length=64)
    rationale: str = Field(min_length=12, max_length=4000)
    decision: Literal['completed', 'not_applicable'] = 'completed'
    scan_id: str | None = None


class WSTGAttestationView(ContractModel):
    id: str
    project_id: str
    scan_id: str | None
    wstg_id: str
    classification: str
    completion_mode: str
    decision: Literal['completed', 'not_applicable']
    evidence_ids: list[str]
    evidence_qualification_id: str
    evidence_qualification_fingerprint: str
    request_fingerprint: str
    created_by_id: str
    created_at: datetime
    replayed: bool


@sync_to_async
def _authorized_project(project_id: str, user_id: str) -> Project:
    project = Project.objects.filter(
        Q(id=project_id) & (Q(owner_id=user_id) | Q(members__id=user_id))
    ).distinct().first()
    if project is None:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project


@sync_to_async
def _coverage(project: Project) -> dict:
    return build_wstg_project_coverage(project)


@router.get('/projects/{project_id}/coverage', response_model=WSTGProjectCoverage)
async def project_wstg_coverage(project_id: str, user=Depends(get_current_user)):
    project = await _authorized_project(project_id, str(user.get('user_id')))
    return await _coverage(project)


@sync_to_async
def _attest(project_id: str, user_id: str, body: WSTGAttestationCreate) -> dict:
    try:
        return create_wstg_methodology_attestation(
            project_id=project_id,
            actor_id=user_id,
            wstg_id=body.wstg_id,
            evidence_ids=body.evidence_ids,
            rationale=body.rationale,
            decision=body.decision,
            scan_id=body.scan_id,
        )
    except WSTGAttestationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post('/projects/{project_id}/attestations', response_model=WSTGAttestationView)
async def attest_wstg_completion(project_id: str, body: WSTGAttestationCreate, user=Depends(get_current_user)):
    await _authorized_project(project_id, str(user.get('user_id')))
    return await _attest(project_id, str(user.get('user_id')), body)
