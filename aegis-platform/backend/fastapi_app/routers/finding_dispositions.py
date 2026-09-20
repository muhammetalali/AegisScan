from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Literal, Optional
from uuid import UUID, uuid4

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from django_project.evidence.models import FindingDisposition
from ..contracts.governed_actions import GovernedActionRequestView
from ..core.dependencies import get_current_user
from ..services.finding_disposition import list_dispositions
from ..services.governed_action_requests import (
    GovernedActionRequestConflict,
    GovernedActionRequestError,
    create_governed_action_request,
    governed_action_request_view,
)
from . import vulnerabilities as vulnerability_routes


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


def _proposal_request_id(request: Request) -> UUID:
    raw = str(request.headers.get('X-Request-ID') or '').strip()
    if not raw:
        return uuid4()
    try:
        return UUID(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail='X-Request-ID must be a valid UUID') from exc


@router.post('/{vuln_id}/dispositions', response_model=GovernedActionRequestView, status_code=202)
async def create_finding_disposition(
    vuln_id: UUID,
    body: FindingDispositionCreate,
    request: Request,
    user=Depends(get_current_user),
):
    user_id = str(user.get('user_id'))
    vulnerability = await vulnerability_routes._get_vulnerability(vuln_id, user_id)
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')

    request_id = _proposal_request_id(request)
    parameters: dict[str, str] = {'rationale': body.rationale}
    if body.disposition in {
        FindingDisposition.Disposition.ACCEPTED_RISK,
        FindingDisposition.Disposition.WONT_FIX,
    }:
        if body.risk_correlation_id is None or body.review_at is None:
            raise HTTPException(
                status_code=422,
                detail='risk_correlation_id and review_at are required for accepted_risk and wont_fix proposals',
            )
        if body.duplicate_of_id is not None:
            raise HTTPException(status_code=422, detail='duplicate_of_id is only valid for duplicate proposals')
        parameters.update({
            'risk_correlation_id': str(body.risk_correlation_id),
            'review_at': body.review_at.astimezone(timezone.utc).isoformat(),
        })
    else:
        if body.duplicate_of_id is None:
            raise HTTPException(status_code=422, detail='duplicate_of_id is required for duplicate proposals')
        if body.risk_correlation_id is not None or body.review_at is not None:
            raise HTTPException(
                status_code=422,
                detail='risk_correlation_id and review_at are not valid for duplicate proposals',
            )
        parameters['duplicate_of_id'] = str(body.duplicate_of_id)

    action_id = f'finding.disposition.{body.disposition}'
    try:
        result = await sync_to_async(create_governed_action_request, thread_sensitive=True)(
            project_id=str(vulnerability.project_id),
            requested_by_id=user_id,
            action_id=action_id,
            entity_type='finding',
            entity_id=str(vulnerability.id),
            expected_version=int(vulnerability.version),
            idempotency_key=f'finding-disposition:{request_id}',
            parameters=parameters,
            correlation_id=request_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except GovernedActionRequestConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GovernedActionRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return GovernedActionRequestView(**governed_action_request_view(result))


@router.get('/{vuln_id}/dispositions', response_model=List[FindingDispositionResponse])
async def get_finding_dispositions(vuln_id: UUID, user=Depends(get_current_user)):
    vulnerability = await vulnerability_routes._get_vulnerability(vuln_id, str(user.get('user_id')))
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    rows = await sync_to_async(list_dispositions, thread_sensitive=True)(finding_id=vuln_id)
    return [_serialize(row) for row in rows]
