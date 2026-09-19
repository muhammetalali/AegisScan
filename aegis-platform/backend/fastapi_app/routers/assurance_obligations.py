from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.assurance_obligation_governance import (
    AssuranceObligationError,
    acknowledge_assurance_obligation,
    assign_assurance_obligation,
    list_assurance_obligations,
    list_review_work_queue,
    materialize_assurance_obligation,
    materialize_recurrence_obligation,
    reconcile_project_assurance_obligations,
    refresh_assurance_obligation,
)

router = APIRouter()


class AssuranceObligationRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schedule_id: UUID | None = None


class AssuranceObligationAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assignee_membership_id: UUID
    expected_version: int = Field(ge=1)


class AssuranceObligationAcknowledgeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expected_version: int = Field(ge=1)


async def _call(func, **kwargs):
    try:
        return await sync_to_async(func)(**kwargs)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AssuranceObligationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def _payload(obligation, replayed=None):
    assigned = None
    if obligation.assigned_to_id:
        assigned = {
            'membership_id': str(obligation.assigned_to_id),
            'user_id': str(obligation.assigned_to.user_id),
            'role': obligation.assigned_to.role,
            'email': str(obligation.assigned_to.user.email),
        }
    result = {
        'id': str(obligation.id),
        'queue_item_id': f'assurance-obligation:{obligation.id}',
        'finding_id': str(obligation.finding_id),
        'kind': obligation.kind,
        'disposition_id': str(obligation.disposition_id) if obligation.disposition_id else None,
        'source_disposition_id': str(obligation.source_disposition_id) if obligation.source_disposition_id else None,
        'source_observation_id': str(obligation.source_observation_id) if obligation.source_observation_id else None,
        'schedule_id': str(obligation.schedule_id),
        'status': obligation.status,
        'priority': obligation.priority,
        'sla_status': obligation.sla_status,
        'escalation_level': obligation.escalation_level,
        'escalation_targets': list(obligation.escalation_targets or []),
        'last_escalated_at': obligation.last_escalated_at.isoformat() if obligation.last_escalated_at else None,
        'policy_id': obligation.policy_id,
        'policy_version': obligation.policy_version,
        'due_at': obligation.due_at.isoformat(),
        'assigned_to': assigned,
        'assigned_at': obligation.assigned_at.isoformat() if obligation.assigned_at else None,
        'assigned_by_user_id': str(obligation.assigned_by_id) if obligation.assigned_by_id else None,
        'acknowledged_at': obligation.acknowledged_at.isoformat() if obligation.acknowledged_at else None,
        'acknowledged_by_user_id': str(obligation.acknowledged_by_id) if obligation.acknowledged_by_id else None,
        'acknowledged': obligation.acknowledged_at is not None,
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


@router.post('/projects/{project_id}/observations/{observation_id}/recurrence-obligation')
async def replay_recurrence_obligation(project_id: UUID, observation_id: UUID, current_user=Depends(get_current_user)):
    result = await _call(
        materialize_recurrence_obligation,
        project_id=str(project_id),
        observation_id=str(observation_id),
        user_id=str(current_user.get('user_id')),
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


@router.post('/projects/{project_id}/obligations/{obligation_id}/assign')
async def assign_obligation(
    project_id: UUID,
    obligation_id: UUID,
    body: AssuranceObligationAssignmentRequest,
    current_user=Depends(get_current_user),
):
    obligation = await _call(
        assign_assurance_obligation,
        project_id=str(project_id),
        obligation_id=str(obligation_id),
        user_id=str(current_user.get('user_id')),
        assignee_membership_id=str(body.assignee_membership_id),
        expected_version=body.expected_version,
    )
    return _payload(obligation)


@router.post('/projects/{project_id}/obligations/{obligation_id}/acknowledge')
async def acknowledge_obligation(
    project_id: UUID,
    obligation_id: UUID,
    body: AssuranceObligationAcknowledgeRequest,
    current_user=Depends(get_current_user),
):
    obligation = await _call(
        acknowledge_assurance_obligation,
        project_id=str(project_id),
        obligation_id=str(obligation_id),
        user_id=str(current_user.get('user_id')),
        expected_version=body.expected_version,
    )
    return _payload(obligation)


@router.get('/projects/{project_id}/work-queue')
async def review_work_queue(
    project_id: UUID,
    mine: bool = False,
    include_terminal: bool = False,
    current_user=Depends(get_current_user),
):
    items = await _call(
        list_review_work_queue,
        project_id=str(project_id),
        user_id=str(current_user.get('user_id')),
        mine=mine,
        include_terminal=include_terminal,
    )
    return {'items': items, 'total': len(items)}


@router.get('/projects/{project_id}/obligations')
async def obligation_list(project_id: UUID, current_user=Depends(get_current_user)):
    items = await _call(
        list_assurance_obligations,
        project_id=str(project_id),
        user_id=str(current_user.get('user_id')),
    )
    return {'items': items, 'total': len(items)}