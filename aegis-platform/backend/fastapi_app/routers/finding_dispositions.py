from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from django_project.evidence.models import FindingDisposition
from django_project.vulnerabilities.models import Vulnerability
from ..core.dependencies import get_current_user
from ..services.finding_disposition import (
    FindingDispositionError,
    govern_finding_disposition,
    list_dispositions,
)
from . import vulnerabilities as vulnerability_routes


# The generic vulnerability PATCH and bulk-update paths already centralize status
# governance in this shared set. Extend that same guard instead of duplicating it.
vulnerability_routes._GOVERNED_STATUS_MUTATIONS.update({
    Vulnerability.Status.ACCEPTED_RISK,
    Vulnerability.Status.WONT_FIX,
    Vulnerability.Status.DUPLICATE,
})

_original_reject = vulnerability_routes._reject_direct_governed_status


def _reject_all_governed_statuses(status: Optional[str]) -> None:
    if status in {
        Vulnerability.Status.ACCEPTED_RISK,
        Vulnerability.Status.WONT_FIX,
        Vulnerability.Status.DUPLICATE,
    }:
        raise vulnerability_routes.GovernedStatusMutationError(
            'accepted_risk/wont_fix/duplicate are governed finding dispositions; '
            'use POST /{vuln_id}/dispositions with immutable tenant/risk lineage.'
        )
    _original_reject(status)


vulnerability_routes._reject_direct_governed_status = _reject_all_governed_statuses

router = APIRouter()


class FindingDispositionCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    disposition: Literal['accepted_risk', 'wont_fix', 'duplicate']
    rationale: str = Field(min_length=3, max_length=2000)
    risk_correlation_id: Optional[UUID] = None
    review_at: Optional[datetime] = None
    duplicate_of_id: Optional[UUID] = None


class FindingDispositionResponse(BaseModel):
    id: str
    finding_id: str
    disposition: str
    organization_id: str
    risk_correlation_id: Optional[str] = None
    duplicate_of_id: Optional[str] = None
    approving_role: str
    policy_version: str
    risk_correlation_sha256: str
    rationale: str
    review_at: Optional[str] = None
    created_by: str
    created_at: str
    replayed: bool = False


def _serialize(row: FindingDisposition, *, replayed: bool = False) -> FindingDispositionResponse:
    return FindingDispositionResponse(
        id=str(row.id),
        finding_id=str(row.finding_id),
        disposition=row.disposition,
        organization_id=str(row.organization_id),
        risk_correlation_id=str(row.risk_correlation_id) if row.risk_correlation_id else None,
        duplicate_of_id=str(row.duplicate_of_id) if row.duplicate_of_id else None,
        approving_role=row.approving_role,
        policy_version=row.policy_version,
        risk_correlation_sha256=row.risk_correlation_sha256,
        rationale=row.rationale,
        review_at=row.review_at.astimezone(timezone.utc).isoformat() if row.review_at else None,
        created_by=str(row.created_by_id),
        created_at=row.created_at.astimezone(timezone.utc).isoformat(),
        replayed=replayed,
    )


@router.post('/{vuln_id}/dispositions', response_model=FindingDispositionResponse, status_code=201)
async def create_finding_disposition(
    vuln_id: UUID,
    body: FindingDispositionCreate,
    response: Response,
    user=Depends(get_current_user),
):
    user_id = str(user.get('user_id'))
    vulnerability = await vulnerability_routes._get_vulnerability(vuln_id, user_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    try:
        result = await sync_to_async(govern_finding_disposition, thread_sensitive=True)(
            finding_id=vuln_id,
            disposition=body.disposition,
            rationale=body.rationale,
            actor_id=user_id,
            risk_correlation_id=body.risk_correlation_id,
            review_at=body.review_at,
            duplicate_of_id=body.duplicate_of_id,
        )
    except FindingDispositionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    response.status_code = 200 if result.replayed else 201
    return _serialize(result.disposition, replayed=result.replayed)


@router.get('/{vuln_id}/dispositions', response_model=List[FindingDispositionResponse])
async def get_finding_dispositions(vuln_id: UUID, user=Depends(get_current_user)):
    vulnerability = await vulnerability_routes._get_vulnerability(vuln_id, str(user.get('user_id')))
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    rows = await sync_to_async(list_dispositions, thread_sensitive=True)(finding_id=vuln_id)
    return [_serialize(row) for row in rows]
