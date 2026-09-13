from __future__ import annotations

from datetime import datetime
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.assurance_obligation_governance import (
    AssuranceObligationError,
    StaleObligationVersion,
    evaluate_obligation_sla,
    get_obligation,
    materialize_expired_risk_obligation,
    materialize_recurrence_obligation,
    satisfy_obligation,
    verify_obligation_chain,
)

router = APIRouter()


class RiskReviewObligationIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    disposition_id: UUID
    now: datetime | None = None


class RecurrenceObligationIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    observation_id: UUID


class ObligationSatisfyIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_version: int = Field(ge=1)
    observation_id: UUID


class ObligationSLAIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    now: datetime | None = None


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, StaleObligationVersion):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


@router.post('/projects/{project_id}/obligations/risk-review')
async def create_risk_review_obligation(project_id: UUID, body: RiskReviewObligationIn, response: Response, current_user=Depends(get_current_user)):
    try:
        result = await sync_to_async(materialize_expired_risk_obligation, thread_sensitive=True)(
            disposition_id=str(body.disposition_id), project_id=str(project_id),
            user_id=str(current_user.get('user_id')), now=body.now,
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc
    response.status_code = 200 if result.replayed else 201
    return await sync_to_async(get_obligation, thread_sensitive=True)(
        obligation_id=str(result.obligation.id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
    )


@router.post('/projects/{project_id}/obligations/recurrence')
async def create_recurrence_obligation(project_id: UUID, body: RecurrenceObligationIn, response: Response, current_user=Depends(get_current_user)):
    try:
        result = await sync_to_async(materialize_recurrence_obligation, thread_sensitive=True)(
            observation_id=str(body.observation_id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc
    response.status_code = 200 if result.replayed else 201
    return await sync_to_async(get_obligation, thread_sensitive=True)(
        obligation_id=str(result.obligation.id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
    )


@router.post('/projects/{project_id}/obligations/evaluate-sla')
async def evaluate_sla(project_id: UUID, body: ObligationSLAIn, current_user=Depends(get_current_user)):
    try:
        changed = await sync_to_async(evaluate_obligation_sla, thread_sensitive=True)(
            project_id=str(project_id), user_id=str(current_user.get('user_id')), now=body.now,
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc
    return {'changed': changed, 'count': len(changed)}


@router.post('/projects/{project_id}/obligations/{obligation_id}/satisfy')
async def satisfy(project_id: UUID, obligation_id: UUID, body: ObligationSatisfyIn, response: Response, current_user=Depends(get_current_user)):
    try:
        result = await sync_to_async(satisfy_obligation, thread_sensitive=True)(
            obligation_id=str(obligation_id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
            expected_version=body.expected_version, observation_id=str(body.observation_id),
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc
    response.status_code = 200
    data = await sync_to_async(get_obligation, thread_sensitive=True)(
        obligation_id=str(result.obligation.id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
    )
    data['replayed'] = result.replayed
    return data


@router.get('/projects/{project_id}/obligations/{obligation_id}')
async def read_obligation(project_id: UUID, obligation_id: UUID, current_user=Depends(get_current_user)):
    try:
        return await sync_to_async(get_obligation, thread_sensitive=True)(
            obligation_id=str(obligation_id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc


@router.get('/projects/{project_id}/obligations/{obligation_id}/audit/verify')
async def verify_audit(project_id: UUID, obligation_id: UUID, current_user=Depends(get_current_user)):
    try:
        return await sync_to_async(verify_obligation_chain, thread_sensitive=True)(
            obligation_id=str(obligation_id), project_id=str(project_id), user_id=str(current_user.get('user_id')),
        )
    except (AssuranceObligationError, PermissionError) as exc:
        raise _error(exc) from exc
