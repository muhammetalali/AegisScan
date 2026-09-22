from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from enterprise.agentic_security_models import AgenticActionDecision, AgenticSecurityProfile

from ..core.dependencies import get_current_user
from ..services.agentic_security import (
    AgenticSecurityAuthorizationError,
    AgenticSecurityConflict,
    AgenticSecurityError,
    authorize_agentic_action,
    register_agentic_profile,
)


router = APIRouter()


class AgenticProfileIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    provider_decision_id: UUID
    agent_name: str = Field(min_length=1, max_length=180)
    agent_version: str = Field(min_length=1, max_length=120)
    model_name: str = Field(min_length=1, max_length=180)
    model_version: str = Field(min_length=1, max_length=120)
    allowed_tools: dict[str, list[str]]
    data_boundaries: dict[str, Any]
    prompt_policy: dict[str, Any]
    idempotency_key: str = Field(min_length=1, max_length=128)


class AgenticActionIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    tool_name: str = Field(min_length=1, max_length=180)
    operation: str = Field(min_length=1, max_length=180)
    prompt_sha256: str = Field(min_length=64, max_length=64)
    prompt_length: int = Field(ge=0, le=200000)
    arguments_sha256: str = Field(min_length=64, max_length=64)
    argument_keys: list[str] = Field(default_factory=list, max_length=128)
    data_labels: list[str] = Field(default_factory=list, max_length=128)
    risk_signals: list[str] = Field(default_factory=list, max_length=32)
    human_approval_ref: str = Field(default='', max_length=255)
    idempotency_key: str = Field(min_length=1, max_length=128)


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


def _serialize_profile(profile: AgenticSecurityProfile) -> dict[str, Any]:
    return {
        'id': str(profile.id),
        'organization_id': str(profile.organization_id),
        'project_id': str(profile.project_id),
        'provider_decision_id': str(profile.provider_governance_decision_id),
        'agent_name': profile.agent_name,
        'agent_version': profile.agent_version,
        'model_name': profile.model_name,
        'model_version': profile.model_version,
        'provider_name': profile.provider_name,
        'provider_version': profile.provider_version,
        'capability': profile.capability,
        'allowed_tools': dict(profile.allowed_tools or {}),
        'data_boundaries': dict(profile.data_boundaries or {}),
        'prompt_policy': dict(profile.prompt_policy or {}),
        'profile_sha256': profile.profile_sha256,
        'request_fingerprint': profile.request_fingerprint,
        'policy_version': profile.policy_version,
        'created_at': profile.created_at.isoformat(),
    }


def _serialize_action(row: AgenticActionDecision) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'profile_id': str(row.profile_id),
        'tool_name': row.tool_name,
        'operation': row.operation,
        'prompt_sha256': row.prompt_sha256,
        'prompt_length': int(row.prompt_length),
        'arguments_sha256': row.arguments_sha256,
        'argument_keys': list(row.argument_keys or []),
        'data_labels': list(row.data_labels or []),
        'risk_signals': list(row.risk_signals or []),
        'human_approval_bound': bool(row.human_approval_ref),
        'decision': row.decision,
        'reason_codes': list(row.reason_codes or []),
        'evidence_sha256': row.evidence_sha256,
        'decision_sha256': row.decision_sha256,
        'request_fingerprint': row.request_fingerprint,
        'policy_version': row.policy_version,
        'created_at': row.created_at.isoformat(),
    }


@router.post('/projects/{project_id}/profiles', status_code=201)
async def create_agentic_profile(
    project_id: UUID,
    payload: AgenticProfileIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(register_agentic_profile)(
            project_id=str(project_id),
            actor_id=actor_id,
            provider_decision_id=str(payload.provider_decision_id),
            agent_name=payload.agent_name,
            agent_version=payload.agent_version,
            model_name=payload.model_name,
            model_version=payload.model_version,
            allowed_tools=payload.allowed_tools,
            data_boundaries=payload.data_boundaries,
            prompt_policy=payload.prompt_policy,
            idempotency_key=payload.idempotency_key,
        )
    except AgenticSecurityAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AgenticSecurityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AgenticSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize_profile(result.profile)}


@router.get('/projects/{project_id}/profiles')
async def list_agentic_profiles(
    project_id: UUID,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        AgenticSecurityProfile.objects.filter(project_id=project_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize_profile(row) for row in rows]


@router.post('/projects/{project_id}/profiles/{profile_id}/actions', status_code=201)
async def evaluate_agentic_action(
    project_id: UUID,
    profile_id: UUID,
    payload: AgenticActionIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(authorize_agentic_action)(
            project_id=str(project_id),
            profile_id=str(profile_id),
            actor_id=actor_id,
            tool_name=payload.tool_name,
            operation=payload.operation,
            prompt_sha256=payload.prompt_sha256,
            prompt_length=payload.prompt_length,
            arguments_sha256=payload.arguments_sha256,
            argument_keys=payload.argument_keys,
            data_labels=payload.data_labels,
            risk_signals=payload.risk_signals,
            human_approval_ref=payload.human_approval_ref,
            idempotency_key=payload.idempotency_key,
        )
    except AgenticSecurityAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AgenticSecurityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AgenticSecurityError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, 'allowed': result.allowed, **_serialize_action(result.decision)}


@router.get('/projects/{project_id}/profiles/{profile_id}/actions')
async def list_agentic_actions(
    project_id: UUID,
    profile_id: UUID,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        AgenticActionDecision.objects.filter(project_id=project_id, profile_id=profile_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize_action(row) for row in rows]
