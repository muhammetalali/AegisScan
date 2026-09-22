from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from enterprise.provider_approval_models import ProviderApprovalDecision

from ..core.dependencies import get_current_user
from ..services.provider_approval import (
    ProviderApprovalAuthorizationError,
    ProviderApprovalConflict,
    ProviderApprovalError,
    evaluate_provider_admissibility,
    record_provider_decision,
)


router = APIRouter()


class ProviderDecisionIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    provider_name: str = Field(min_length=1, max_length=180)
    provider_version: str = Field(min_length=1, max_length=120)
    capability: str = Field(min_length=1, max_length=180)
    status: str = Field(min_length=1, max_length=20)
    manifest: dict[str, Any]
    rationale: str = Field(default='', max_length=5000)
    expires_at: datetime | None = None


class ProviderEvaluationIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    provider_name: str = Field(min_length=1, max_length=180)
    provider_version: str = Field(min_length=1, max_length=120)
    capability: str = Field(min_length=1, max_length=180)
    expected_legacy_approval_id: UUID | None = None
    expected_decision_id: UUID | None = None


def _actor_id(user: dict[str, Any]) -> str:
    value = user.get('user_id') or user.get('id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user.')
    return str(value)


@sync_to_async
def _project_access(project_id: str, actor_id: str) -> bool:
    return Project.objects.filter(pk=project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).distinct().exists()


def _serialize(decision: ProviderApprovalDecision) -> dict[str, Any]:
    return {
        'id': str(decision.id),
        'organization_id': str(decision.organization_id),
        'project_id': str(decision.project_id),
        'legacy_approval_id': str(decision.legacy_approval_id or ''),
        'predecessor_id': str(decision.predecessor_id or ''),
        'provider_name': decision.provider_name,
        'provider_version': decision.provider_version,
        'capability': decision.capability,
        'provider_identity_sha256': decision.provider_identity_sha256,
        'status': decision.status,
        'trust_state': decision.trust_state,
        'decision_version': int(decision.decision_version),
        'manifest_sha256': decision.manifest_sha256,
        'capability_manifest': dict(decision.capability_manifest or {}),
        'capability_manifest_sha256': decision.capability_manifest_sha256,
        'supply_chain_evidence': dict(decision.supply_chain_evidence or {}),
        'supply_chain_sha256': decision.supply_chain_sha256,
        'request_fingerprint': decision.request_fingerprint,
        'policy_version': decision.policy_version,
        'rationale': decision.rationale,
        'expires_at': decision.expires_at.isoformat() if decision.expires_at else None,
        'created_at': decision.created_at.isoformat(),
    }


@router.post('/projects/{project_id}/decisions', status_code=201)
async def create_provider_decision(
    project_id: UUID,
    payload: ProviderDecisionIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(record_provider_decision)(
            project_id=str(project_id),
            actor_id=actor_id,
            provider_name=payload.provider_name,
            provider_version=payload.provider_version,
            capability=payload.capability,
            status=payload.status,
            manifest=payload.manifest,
            rationale=payload.rationale,
            expires_at=payload.expires_at,
        )
    except ProviderApprovalAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ProviderApprovalConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ProviderApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize(result.decision)}


@router.get('/projects/{project_id}/decisions')
async def list_provider_decisions(
    project_id: UUID,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        ProviderApprovalDecision.objects.filter(project_id=project_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize(row) for row in rows]


@router.post('/projects/{project_id}/evaluate')
async def evaluate_provider_decision(
    project_id: UUID,
    payload: ProviderEvaluationIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    return await sync_to_async(evaluate_provider_admissibility)(
        project_id=str(project_id),
        provider_name=payload.provider_name,
        provider_version=payload.provider_version,
        capability=payload.capability,
        expected_legacy_approval_id=(
            str(payload.expected_legacy_approval_id)
            if payload.expected_legacy_approval_id else None
        ),
        expected_decision_id=(
            str(payload.expected_decision_id)
            if payload.expected_decision_id else None
        ),
    )
