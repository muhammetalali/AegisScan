from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import RiskCorrelationSnapshot

from ..core.dependencies import get_current_user
from ..services.risk_correlation import ANALYSIS_VERSION, correlate_finding

router = APIRouter()


class CorrelationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scan_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)
    limit: int = Field(default=200, ge=1, le=500)


class RiskCorrelationItem(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str
    project_id: str
    finding_id: str
    finding_intelligence_id: str
    source_snapshot_id: str
    attack_path_id: str | None = None
    analysis_version: str
    score: float
    priority: str
    components: dict[str, Any]
    evidence_count: int
    source_snapshot_sha256: str
    correlation_sha256: str
    created_at: str


class CorrelationRunResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')
    contract_version: str = '1.0'
    source: str = 'postgresql'
    project_id: str
    analysis_version: str = ANALYSIS_VERSION
    analyzed: int
    created: int
    reused: int
    failures: list[dict[str, str]]
    items: list[RiskCorrelationItem]


def _serialize(row: RiskCorrelationSnapshot) -> RiskCorrelationItem:
    return RiskCorrelationItem(
        id=str(row.id),
        project_id=str(row.project_id),
        finding_id=str(row.vulnerability_id),
        finding_intelligence_id=str(row.finding_intelligence_id),
        source_snapshot_id=str(row.source_snapshot_id),
        attack_path_id=str(row.attack_path_id) if row.attack_path_id else None,
        analysis_version=row.analysis_version,
        score=float(row.score),
        priority=row.priority,
        components=row.components or {},
        evidence_count=row.evidence_count,
        source_snapshot_sha256=row.source_snapshot_sha256,
        correlation_sha256=row.correlation_sha256,
        created_at=row.created_at.isoformat(),
    )


def _project_for_user(project_id: str, user_id: str):
    return (
        Project.objects
        .filter(id=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )


@sync_to_async
def _correlate_project(
    project_id: str,
    user_id: str,
    request: CorrelationRequest,
) -> CorrelationRunResponse:
    project = _project_for_user(project_id, user_id)
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')

    qs = (
        Vulnerability.objects
        .filter(project=project)
        .exclude(cve_ids=[])
        .select_related('scan', 'asset')
        .order_by('-risk_score', '-created_at', 'id')
    )
    if request.scan_id:
        qs = qs.filter(scan_id=request.scan_id)
    if request.finding_ids:
        qs = qs.filter(id__in=request.finding_ids)

    findings = list(qs[:request.limit])
    items: list[RiskCorrelationItem] = []
    failures: list[dict[str, str]] = []
    created_count = 0

    for finding in findings:
        try:
            row, created = correlate_finding(finding, actor_id=user_id)
        except ValueError as exc:
            failures.append({'finding_id': str(finding.id), 'error': str(exc)})
            continue
        created_count += int(created)
        items.append(_serialize(row))

    items.sort(key=lambda item: (item.score, item.priority, item.finding_id), reverse=True)
    return CorrelationRunResponse(
        project_id=str(project.id),
        analyzed=len(findings),
        created=created_count,
        reused=len(items) - created_count,
        failures=failures,
        items=items,
    )


@sync_to_async
def _latest_project(
    project_id: str,
    user_id: str,
    scan_id: str | None,
    limit: int,
) -> list[RiskCorrelationItem]:
    project = _project_for_user(project_id, user_id)
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')

    qs = (
        RiskCorrelationSnapshot.objects
        .filter(project=project)
        .select_related('vulnerability')
        .order_by('-created_at', '-id')
    )
    if scan_id:
        qs = qs.filter(vulnerability__scan_id=scan_id)

    latest: list[RiskCorrelationItem] = []
    seen: set[str] = set()
    for row in qs:
        finding_id = str(row.vulnerability_id)
        if finding_id in seen:
            continue
        seen.add(finding_id)
        latest.append(_serialize(row))
        if len(latest) >= limit:
            break
    latest.sort(key=lambda item: (item.score, item.priority, item.finding_id), reverse=True)
    return latest


@sync_to_async
def _latest_finding(finding_id: str, user_id: str) -> RiskCorrelationItem:
    finding = (
        Vulnerability.objects
        .filter(id=finding_id)
        .filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id))
        .distinct()
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found or inaccessible')
    row = (
        RiskCorrelationSnapshot.objects
        .filter(vulnerability=finding)
        .order_by('-created_at', '-id')
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail='No persisted risk correlation found')
    return _serialize(row)


@router.post('/projects/{project_id}/correlate', response_model=CorrelationRunResponse)
async def correlate_project(
    project_id: str,
    request: CorrelationRequest,
    user=Depends(get_current_user),
):
    return await _correlate_project(project_id, str(user.get('user_id')), request)


@router.get('/projects/{project_id}', response_model=list[RiskCorrelationItem])
async def latest_project_correlations(
    project_id: str,
    scan_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    user=Depends(get_current_user),
):
    return await _latest_project(project_id, str(user.get('user_id')), scan_id, limit)


@router.get('/findings/{finding_id}/latest', response_model=RiskCorrelationItem)
async def latest_finding_correlation(
    finding_id: str,
    user=Depends(get_current_user),
):
    return await _latest_finding(finding_id, str(user.get('user_id')))
