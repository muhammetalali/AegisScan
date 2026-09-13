from __future__ import annotations

from datetime import datetime
from typing import Any

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from fastapi_app.core.dependencies import get_current_user
from fastapi_app.services.security_operations import (
    SecurityOperationsError,
    StaleCaseVersion,
    attach_decision_action,
    get_case_state,
    ingest_detection_signal,
    transition_case,
    verify_case_chain,
)

router = APIRouter()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class SignalIn(StrictModel):
    revision_id: str = Field(min_length=1, max_length=64)
    event: dict[str, Any]
    observed_at: datetime
    source: str = Field(default='siem', pattern=r'^(siem|edr|replay|sensor)$')


class CaseTransitionIn(StrictModel):
    expected_version: int = Field(ge=1)
    status: str = Field(pattern=r'^(investigating|decided|closed)$')
    decision_summary: str = Field(default='', max_length=8000)


class ResponseHandoffIn(StrictModel):
    action_id: str = Field(min_length=1, max_length=255)
    expected_version: int = Field(ge=1)


def _uid(user: dict[str, Any]) -> str:
    value = user.get('user_id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user')
    return str(value)


def _raise(exc: Exception):
    if isinstance(exc, StaleCaseVersion):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post('/projects/{project_id}/signals', status_code=201)
async def ingest_signal(project_id: str, payload: SignalIn, response: Response, user=Depends(get_current_user)):
    try:
        result = await sync_to_async(ingest_detection_signal)(
            revision_id=payload.revision_id, project_id=project_id, user_id=_uid(user),
            event=payload.event, observed_at=payload.observed_at, source=payload.source,
        )
    except (SecurityOperationsError, PermissionError) as exc:
        _raise(exc)
    if result.replayed:
        response.status_code = 200
    return {
        'signal_id': str(result.signal.id), 'fingerprint': result.signal.fingerprint,
        'case_id': str(result.case.id), 'case_status': result.case.status,
        'case_version': result.state.version, 'generation': result.state.generation,
        'replayed': result.replayed, 'case_created': result.case_created,
    }


@router.get('/projects/{project_id}/cases/{case_id}')
async def case_state(project_id: str, case_id: str, user=Depends(get_current_user)):
    try:
        return await sync_to_async(get_case_state)(case_id=case_id, project_id=project_id, user_id=_uid(user))
    except (SecurityOperationsError, PermissionError) as exc:
        _raise(exc)


@router.post('/projects/{project_id}/cases/{case_id}/transition')
async def case_transition(project_id: str, case_id: str, payload: CaseTransitionIn, user=Depends(get_current_user)):
    try:
        state = await sync_to_async(transition_case)(
            case_id=case_id, project_id=project_id, user_id=_uid(user), expected_version=payload.expected_version,
            status=payload.status, decision_summary=payload.decision_summary,
        )
    except (SecurityOperationsError, PermissionError) as exc:
        _raise(exc)
    return {'case_id': str(state.case_id), 'status': state.case.status, 'version': state.version, 'generation': state.generation}


@router.post('/projects/{project_id}/cases/{case_id}/response-action')
async def response_handoff(project_id: str, case_id: str, payload: ResponseHandoffIn, response: Response, user=Depends(get_current_user)):
    try:
        state, replayed = await sync_to_async(attach_decision_action)(
            case_id=case_id, action_id=payload.action_id, project_id=project_id,
            user_id=_uid(user), expected_version=payload.expected_version,
        )
    except (SecurityOperationsError, PermissionError) as exc:
        _raise(exc)
    if replayed:
        response.status_code = 200
    return {'case_id': str(state.case_id), 'decision_action_id': state.decision_action_id, 'version': state.version, 'replayed': replayed}


@router.get('/projects/{project_id}/cases/{case_id}/audit/verify')
async def audit_verify(project_id: str, case_id: str, user=Depends(get_current_user)):
    try:
        return await sync_to_async(verify_case_chain)(case_id=case_id, project_id=project_id, user_id=_uid(user))
    except (SecurityOperationsError, PermissionError) as exc:
        _raise(exc)
