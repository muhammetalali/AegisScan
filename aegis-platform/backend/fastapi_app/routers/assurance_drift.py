from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.assurance_drift_governance import AssuranceDriftError, get_assurance_condition, record_assurance_observation

router = APIRouter()


class AssuranceObservationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    execution_id: UUID
    finding_id: UUID
    finding_present: bool
    material: dict = Field(default_factory=dict)
    evidence_id: UUID | None = None


async def _call(func, **kwargs):
    try:
        return await sync_to_async(func)(**kwargs)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AssuranceDriftError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post('/projects/{project_id}/observations')
async def create_observation(project_id: UUID, body: AssuranceObservationRequest, current_user=Depends(get_current_user)):
    result = await _call(
        record_assurance_observation,
        execution_id=str(body.execution_id), project_id=str(project_id), finding_id=str(body.finding_id),
        user_id=str(current_user.get('user_id')), finding_present=body.finding_present,
        material=body.material, evidence_id=str(body.evidence_id) if body.evidence_id else None,
    )
    return {
        'observation_id': str(result.observation.id),
        'classification': result.observation.classification,
        'generation': result.state.generation,
        'version': result.state.version,
        'state': result.state.state,
        'replayed': result.replayed,
        'prior_closure_id': str(result.observation.prior_closure_id) if result.observation.prior_closure_id else None,
        'prior_disposition_id': str(result.observation.prior_disposition_id) if result.observation.prior_disposition_id else None,
    }


@router.get('/projects/{project_id}/findings/{finding_id}')
async def condition_state(project_id: UUID, finding_id: UUID, current_user=Depends(get_current_user)):
    return await _call(
        get_assurance_condition,
        project_id=str(project_id), finding_id=str(finding_id), user_id=str(current_user.get('user_id')),
    )
