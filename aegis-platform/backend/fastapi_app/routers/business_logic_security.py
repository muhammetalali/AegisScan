from __future__ import annotations

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query

from enterprise.governed_action_models import BusinessLogicAssessment

from ..core.dependencies import get_current_user
from ..services.business_logic_security import (
    BusinessLogicAssessmentError,
    assess_governed_action_request,
    serialize_business_logic_assessment,
)

router = APIRouter()


def _actor_id(user) -> str:
    actor = str(user.get('user_id') or user.get('id') or '').strip()
    if not actor:
        raise HTTPException(status_code=401, detail='Authenticated user id is missing')
    return actor


@sync_to_async
def _assess(request_id: str, actor_id: str) -> dict:
    result = assess_governed_action_request(
        request_id=request_id,
        assessed_by_id=actor_id,
    )
    return serialize_business_logic_assessment(result)


@sync_to_async
def _list(request_id: str, actor_id: str, limit: int) -> list[dict]:
    from django.db.models import Q
    from django_project.projects.models import Project
    from enterprise.models import OrganizationMembership

    row = (
        BusinessLogicAssessment.objects.filter(request_id=request_id)
        .select_related('organization', 'project')
        .order_by('-created_at', '-id')
        .first()
    )
    if row is None:
        return []
    membership = OrganizationMembership.objects.filter(
        organization=row.organization,
        user_id=actor_id,
        user__is_active=True,
        is_active=True,
    ).exists()
    project_access = Project.objects.filter(pk=row.project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).exists()
    if not membership or not project_access:
        raise PermissionError('Active tenant and project membership are required for business-logic assessment reads.')
    rows = (
        BusinessLogicAssessment.objects.filter(request_id=request_id)
        .select_related('organization', 'project', 'request', 'assessed_by')
        .order_by('-created_at', '-id')[:limit]
    )
    return [serialize_business_logic_assessment(item) for item in rows]


@router.post('/requests/{request_id}/assess', status_code=201)
async def assess_request(
    request_id: str,
    user=Depends(get_current_user),
):
    try:
        return await _assess(request_id, _actor_id(user))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except BusinessLogicAssessmentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/requests/{request_id}/assessments')
async def list_assessments(
    request_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(get_current_user),
):
    try:
        return await _list(request_id, _actor_id(user), limit)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
