from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from ..core.dependencies import get_current_user
from ..services.assurance_obligation_governance import (
    AssuranceObligationError,
    list_assurance_obligations,
    materialize_assurance_obligation,
    reconcile_project_assurance_obligations,
    refresh_assurance_obligation,
)

router = APIRouter()


class AssuranceObligationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schedule_id: UUID | None = None


async def _call(func, **kwargs):
    try:
        return await sync_to_async(func)(**kwargs)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AssuranceObligationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _payload(obligation, replayed=None):
    result = {
        'id': str(obligation.id),
        'finding_id': str(obligation.finding_id),
        'disposition_id': str(obligation.disposition_id),
        'schedule_id': str(obligation.schedule_id),
        'status': obligation.status,
        'due_at': obligation.due_at.isoformat(),
        'generation': obligation.generation,
        'version': obligation.version,
        'last_execution_id': str(obligation.last_execution_id) if obligation.last_execution_id else None,
        'last_observation_id': str(obligation.last_observation_id) if obligation.last_observation_id else None,
        'satisfied_at': obligation.satisfied_at.isoformat() if obligation.satisfied_at else None,
        'superseded_at': obligation.superseded_at.isoformat() if obligation.superseded_at else None,
    }
    if replayed is not None:
        result['replayed'] = replayed
    return result


@router.post('/projects/{project_id}/findings/{finding_id}/obligations')
async def create_obligation(project_id: UUID, finding_id: UUID, body: AssuranceObligationRequest, current_user=Depends(get_current_user)):
    result = await _call(
        materialize_assurance_obligation,
        project_id=str(project_id),
        finding_id=str(finding_id),
        user_id=str(current_user.get('user_id')),
        schedule_id=str(body.schedule_id) if body.schedule_id else None,
    )
    return _payload(result.obligation, result.replayed)


@router.post('/projects/{project_id}/obligations/reconcile')
async def reconcile_obligations(project_id: UUID, current_user=Depends(get_current_user)):
    result = await _call(
        reconcile_project_assurance_obligations,
        project_id=str(project_id),
        user_id=str(current_user.get('user_id')),
    )
    return {
        'materialized': result.materialized,
        'refreshed': result.refreshed,
        'satisfied': result.satisfied,
        'overdue': result.overdue,
        'superseded': result.superseded,
    }


@router.post('/projects/{project_id}/obligations/{obligation_id}/refresh')
async def refresh_obligation(project_id: UUID, obligation_id: UUID, current_user=Depends(get_current_user)):
    obligation = await _call(
        refresh_assurance_obligation,
        project_id=str(project_id),
        obligation_id=str(obligation_id),
        user_id=str(current_user.get('user_id')),
    )
    return _payload(obligation)


@router.get('/projects/{project_id}/obligations')
async def obligation_list(project_id: UUID, current_user=Depends(get_current_user)):
    items = await _call(
        list_assurance_obligations,
        project_id=str(project_id),
        user_id=str(current_user.get('user_id')),
    )
    return {'items': items, 'total': len(items)}
