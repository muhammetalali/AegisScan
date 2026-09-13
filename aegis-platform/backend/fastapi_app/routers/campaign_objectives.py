from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.campaign_objective_assurance import (
    CampaignAssuranceError,
    StaleCampaignVersion,
    StaleObjectiveVersion,
    add_objective,
    campaign_summary,
    create_campaign,
    verify_campaign_chain,
)
from ..services.governed_action_executor import execute_governed_action, governed_action_view
from .governed_action_execution import translate_governed_action_error

router = APIRouter()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class CampaignCreateIn(_StrictModel):
    name: str = Field(min_length=1, max_length=240)
    source_asset_id: str


class ObjectiveCreateIn(_StrictModel):
    expected_campaign_version: int = Field(ge=1)
    target_asset_id: str
    title: str = Field(min_length=1, max_length=240)
    objective_type: str = Field(default='crown_jewel_access', min_length=1, max_length=80)
    success_criteria: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list)


class ObjectiveAssessmentIn(_StrictModel):
    expected_objective_version: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    correlation_id: UUID | None = None
    attack_path_id: str
    evidence_id: str
    outcome: Literal['reached', 'blocked', 'inconclusive']
    reason_code: str = Field(min_length=1, max_length=80)
    explanation: str = ''
    blast_radius_snapshot_id: str | None = None
    validation_id: str | None = None


class CampaignCompleteIn(_StrictModel):
    expected_campaign_version: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    correlation_id: UUID | None = None


def _translate(exc: Exception):
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, (StaleCampaignVersion, StaleObjectiveVersion)):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, CampaignAssuranceError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


def _request_ip(request: Request) -> str:
    value = str(request.client.host if request.client else '').strip()
    return value if value.count('.') == 3 else '127.0.0.1'


@router.post('/projects/{project_id}', status_code=201)
async def create_campaign_api(project_id: str, body: CampaignCreateIn, current_user=Depends(get_current_user)):
    try:
        campaign = await sync_to_async(create_campaign)(
            project_id=project_id,
            user_id=str(current_user.get('user_id')),
            name=body.name,
            source_asset_id=body.source_asset_id,
        )
        return {'id': str(campaign.id), 'status': campaign.status, 'version': campaign.version, 'scope_sha256': campaign.scope_sha256}
    except Exception as exc:  # noqa: BLE001
        _translate(exc)


@router.post('/projects/{project_id}/{campaign_id}/objectives', status_code=201)
async def add_objective_api(project_id: str, campaign_id: str, body: ObjectiveCreateIn, current_user=Depends(get_current_user)):
    try:
        objective, replayed = await sync_to_async(add_objective)(
            campaign_id=campaign_id,
            project_id=project_id,
            user_id=str(current_user.get('user_id')),
            expected_campaign_version=body.expected_campaign_version,
            target_asset_id=body.target_asset_id,
            title=body.title,
            objective_type=body.objective_type,
            success_criteria=body.success_criteria,
            attack_techniques=body.attack_techniques,
        )
        return {'id': str(objective.id), 'status': objective.status, 'version': objective.version, 'generation': objective.generation, 'replayed': replayed}
    except Exception as exc:  # noqa: BLE001
        _translate(exc)


@router.post('/projects/{project_id}/{campaign_id}/objectives/{objective_id}/assessments', status_code=201)
async def assess_objective_api(
    project_id: str,
    campaign_id: str,
    objective_id: str,
    body: ObjectiveAssessmentIn,
    request: Request,
    current_user=Depends(get_current_user),
):
    try:
        result = await sync_to_async(execute_governed_action)(
            action_id='campaign.objective.assess',
            project_id=project_id,
            actor_id=str(current_user.get('user_id')),
            entity_type='crown_jewel_objective',
            entity_id=objective_id,
            expected_version=body.expected_objective_version,
            idempotency_key=body.idempotency_key,
            correlation_id=body.correlation_id,
            parameters={
                'campaign_id': campaign_id,
                'attack_path_id': body.attack_path_id,
                'evidence_id': body.evidence_id,
                'outcome': body.outcome,
                'reason_code': body.reason_code,
                'explanation': body.explanation,
                'blast_radius_snapshot_id': body.blast_radius_snapshot_id,
                'validation_id': body.validation_id,
            },
            ip_address=_request_ip(request),
            user_agent=request.headers.get('user-agent', ''),
            session_id=request.cookies.get('sessionid', ''),
        )
        view = governed_action_view(result)
        payload = view['result']
        return {
            'id': payload['id'],
            'outcome': payload['outcome'],
            'proof_sha256': payload['proof_sha256'],
            'objective_version': payload['objective_version'],
            'objective_generation': payload['objective_generation'],
            'replayed': bool(result.replayed or payload.get('domain_replayed')),
            'execution_id': view['execution_id'],
            'execution_fingerprint': view['execution_fingerprint'],
            'audit_entry_hash': view['audit']['entry_hash'],
            'correlation_id': str(view['correlation_id']),
        }
    except Exception as exc:  # noqa: BLE001
        translate_governed_action_error(exc)


@router.post('/projects/{project_id}/{campaign_id}/complete')
async def complete_campaign_api(
    project_id: str,
    campaign_id: str,
    body: CampaignCompleteIn,
    request: Request,
    current_user=Depends(get_current_user),
):
    try:
        result = await sync_to_async(execute_governed_action)(
            action_id='campaign.complete',
            project_id=project_id,
            actor_id=str(current_user.get('user_id')),
            entity_type='campaign',
            entity_id=campaign_id,
            expected_version=body.expected_campaign_version,
            idempotency_key=body.idempotency_key,
            correlation_id=body.correlation_id,
            parameters={},
            ip_address=_request_ip(request),
            user_agent=request.headers.get('user-agent', ''),
            session_id=request.cookies.get('sessionid', ''),
        )
        view = governed_action_view(result)
        payload = view['result']
        return {
            'id': payload['id'],
            'status': payload['status'],
            'version': payload['version'],
            'completion_sha256': payload['completion_sha256'],
            'replayed': result.replayed,
            'execution_id': view['execution_id'],
            'execution_fingerprint': view['execution_fingerprint'],
            'audit_entry_hash': view['audit']['entry_hash'],
            'correlation_id': str(view['correlation_id']),
        }
    except Exception as exc:  # noqa: BLE001
        translate_governed_action_error(exc)


@router.get('/projects/{project_id}/{campaign_id}')
async def campaign_summary_api(project_id: str, campaign_id: str, current_user=Depends(get_current_user)):
    try:
        return await sync_to_async(campaign_summary)(campaign_id=campaign_id, project_id=project_id, user_id=str(current_user.get('user_id')))
    except Exception as exc:  # noqa: BLE001
        _translate(exc)


@router.get('/projects/{project_id}/{campaign_id}/audit/verify')
async def campaign_audit_verify_api(project_id: str, campaign_id: str, current_user=Depends(get_current_user)):
    try:
        return await sync_to_async(verify_campaign_chain)(campaign_id=campaign_id, project_id=project_id, user_id=str(current_user.get('user_id')))
    except Exception as exc:  # noqa: BLE001
        _translate(exc)
