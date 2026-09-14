from __future__ import annotations

from typing import Literal

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from django_project.projects.models import Project

from ..core.dependencies import get_current_user
from ..services.wstg_reporting import build_wstg_project_coverage

router = APIRouter()


class ContractModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class WSTGGroupCoverage(ContractModel):
    total: int
    observed: int
    observation_coverage_percent: float


class WSTGCoverageSummary(ContractModel):
    total_tests: int
    observed_tests: int
    observation_coverage_percent: float
    auto_assisted_total: int
    auto_assisted_observed: int
    auto_assisted_observation_coverage_percent: float
    trusted_evidence_records: int
    trusted_finding_records: int
    rejected_lineage_records: int
    states: dict[str, int]


class WSTGTestCoverage(ContractModel):
    wstg_id: str
    category: str
    title: str
    classification: str
    state: Literal['observed', 'not_observed', 'manual_required', 'blocked_native_gap', 'inconclusive']
    has_observation: bool
    evidence_records: int
    finding_records: int
    capability_ids: list[str]
    latest_observed_at: str | None
    completion_claim_allowed: Literal[False]


class WSTGProjectCoverage(ContractModel):
    contract_version: Literal['1.0']
    methodology: Literal['WSTG']
    methodology_version: Literal['4.2']
    source: Literal['postgresql']
    project_id: str
    project_name: str
    claim_policy: Literal['observation-only']
    completion_claim_allowed: Literal[False]
    finding_state_authority: Literal['governed-finding-confirmation']
    summary: WSTGCoverageSummary
    category_summary: dict[str, WSTGGroupCoverage]
    classification_summary: dict[str, WSTGGroupCoverage]
    tests: list[WSTGTestCoverage]


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
