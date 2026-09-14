from __future__ import annotations

from typing import Literal

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project

from ..core.dependencies import get_current_user
from ..services.wstg_reporting import build_wstg_project_coverage

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
    completion_claim_allowed: Literal[False]


class WSTGProjectCoverage(ContractModel):
    contract_version: Literal['1.0']
    methodology: Literal['WSTG']
    methodology_version: Literal['4.2']
    source: Literal['postgresql']
    project_id: str
    project_name: str
    scope_scan_id: str | None
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
