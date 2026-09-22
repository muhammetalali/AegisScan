from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from enterprise.attack_replay_models import AttackReplayRun, AttackReplayScenario

from ..core.dependencies import get_current_user
from ..services.attack_replay_sandbox import (
    AttackReplayAuthorizationError,
    AttackReplayConflict,
    AttackReplayError,
    create_attack_replay_scenario,
    run_attack_replay,
)


router = APIRouter()


class ExpectedControlIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    control_id: str = Field(min_length=1, max_length=180)
    expected: str = Field(min_length=1, max_length=32)


class ObservedControlIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    control_id: str = Field(min_length=1, max_length=180)
    observed: str = Field(min_length=1, max_length=32)
    evidence_ids: list[UUID] = Field(min_length=1, max_length=64)


class AttackReplayScenarioIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    attack_path_validation_id: UUID
    expected_controls: list[ExpectedControlIn] = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)


class AttackReplayRunIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    observed_controls: list[ObservedControlIn] = Field(default_factory=list, max_length=128)
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


def _serialize_scenario(row: AttackReplayScenario) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'attack_path_validation_id': str(row.attack_path_validation_id),
        'isolation_contract': dict(row.isolation_contract or {}),
        'source_snapshot': dict(row.source_snapshot or {}),
        'expected_controls': list(row.expected_controls or []),
        'scenario_sha256': row.scenario_sha256,
        'request_fingerprint': row.request_fingerprint,
        'policy_version': row.policy_version,
        'created_at': row.created_at.isoformat(),
    }


def _serialize_run(row: AttackReplayRun) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'scenario_id': str(row.scenario_id),
        'outcome': row.outcome,
        'observed_controls': list(row.observed_controls or []),
        'observation_evidence': list(row.observation_evidence or []),
        'result_snapshot': dict(row.result_snapshot or {}),
        'input_sha256': row.input_sha256,
        'result_sha256': row.result_sha256,
        'comparison_sha256': row.comparison_sha256,
        'request_fingerprint': row.request_fingerprint,
        'policy_version': row.policy_version,
        'created_at': row.created_at.isoformat(),
    }


@router.post('/projects/{project_id}/scenarios', status_code=201)
async def create_replay_scenario(
    project_id: UUID,
    payload: AttackReplayScenarioIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(create_attack_replay_scenario)(
            project_id=str(project_id),
            actor_id=actor_id,
            attack_path_validation_id=str(payload.attack_path_validation_id),
            expected_controls=[row.model_dump() for row in payload.expected_controls],
            idempotency_key=payload.idempotency_key,
        )
    except AttackReplayAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AttackReplayConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AttackReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize_scenario(result.scenario)}


@router.get('/projects/{project_id}/scenarios')
async def list_replay_scenarios(
    project_id: UUID,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        AttackReplayScenario.objects.filter(project_id=project_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize_scenario(row) for row in rows]


@router.post('/projects/{project_id}/scenarios/{scenario_id}/runs', status_code=201)
async def execute_replay_scenario(
    project_id: UUID,
    scenario_id: UUID,
    payload: AttackReplayRunIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(run_attack_replay)(
            project_id=str(project_id),
            scenario_id=str(scenario_id),
            actor_id=actor_id,
            observed_controls=[
                {
                    'control_id': row.control_id,
                    'observed': row.observed,
                    'evidence_ids': [str(item) for item in row.evidence_ids],
                }
                for row in payload.observed_controls
            ],
            idempotency_key=payload.idempotency_key,
        )
    except AttackReplayAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except AttackReplayConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AttackReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize_run(result.run)}


@router.get('/projects/{project_id}/scenarios/{scenario_id}/runs')
async def list_replay_runs(
    project_id: UUID,
    scenario_id: UUID,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        AttackReplayRun.objects.filter(project_id=project_id, scenario_id=scenario_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize_run(row) for row in rows]
