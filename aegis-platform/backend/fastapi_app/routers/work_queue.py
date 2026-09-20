from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.governed_work_queue import (
    GovernedWorkQueueConflict,
    GovernedWorkQueueError,
    StaleGovernedWorkClaimVersion,
    list_governed_work,
    mutate_governed_work_claim,
)


router = APIRouter()


class WorkClaimMutation(BaseModel):
    model_config = ConfigDict(extra='forbid')

    project_id: UUID
    expected_claim_version: int = Field(ge=0)
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$')
    lease_seconds: int | None = Field(default=None, ge=60, le=86400)


def _actor_id(user: dict) -> str:
    actor = str(user.get('user_id') or '').strip()
    if not actor:
        raise HTTPException(status_code=401, detail='Authenticated user id is missing.')
    return actor


async def _mutate(*, operation: str, source_type: str, source_id: str, body: WorkClaimMutation, user: dict):
    if operation in {'claim', 'renew'} and body.lease_seconds is None:
        raise HTTPException(status_code=422, detail='lease_seconds is required for claim and renew.')
    try:
        result = await sync_to_async(mutate_governed_work_claim, thread_sensitive=True)(
            actor_id=_actor_id(user),
            project_id=str(body.project_id),
            source_type=source_type,
            source_id=source_id,
            operation=operation,
            expected_version=body.expected_claim_version,
            idempotency_key=body.idempotency_key,
            lease_seconds=body.lease_seconds,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (StaleGovernedWorkClaimVersion, GovernedWorkQueueConflict) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GovernedWorkQueueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    payload = dict(result.snapshot)
    payload['replayed'] = result.replayed
    return payload


@router.get('')
async def work_queue(
    project_id: UUID | None = None,
    source_type: str | None = None,
    claim_state: str | None = None,
    limit: int = Query(default=200, ge=1, le=500),
    user=Depends(get_current_user),
):
    try:
        return await sync_to_async(list_governed_work, thread_sensitive=True)(
            actor_id=_actor_id(user),
            project_id=str(project_id) if project_id else None,
            source_type=source_type,
            claim_state=claim_state,
            limit=limit,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except GovernedWorkQueueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post('/{source_type}/{source_id}/claim')
async def claim_work(source_type: str, source_id: str, body: WorkClaimMutation, user=Depends(get_current_user)):
    return await _mutate(operation='claim', source_type=source_type, source_id=source_id, body=body, user=user)


@router.post('/{source_type}/{source_id}/renew')
async def renew_work(source_type: str, source_id: str, body: WorkClaimMutation, user=Depends(get_current_user)):
    return await _mutate(operation='renew', source_type=source_type, source_id=source_id, body=body, user=user)


@router.post('/{source_type}/{source_id}/release')
async def release_work(source_type: str, source_id: str, body: WorkClaimMutation, user=Depends(get_current_user)):
    if body.lease_seconds is not None:
        raise HTTPException(status_code=422, detail='lease_seconds must be omitted for release.')
    return await _mutate(operation='release', source_type=source_type, source_id=source_id, body=body, user=user)
