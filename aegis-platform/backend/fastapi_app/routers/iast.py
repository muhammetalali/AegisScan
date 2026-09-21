from __future__ import annotations

from typing import Literal

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.dependencies import get_current_user
from ..services.iast_security import (
    IASTAuthorizationError,
    IASTConflict,
    IASTError,
    ingest_iast_observation,
    start_iast_session,
)


router = APIRouter()


class IASTSessionRequest(BaseModel):
    project_id: str
    asset_id: str
    scan_id: str
    authorization_id: str
    provider_identity: str = Field(min_length=1, max_length=255)
    instrumentation_mode: Literal['agent', 'sdk', 'sidecar']
    idempotency_key: str = Field(min_length=1, max_length=128)


class IASTObservationRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=128)
    observation_kind: Literal['taint-flow', 'runtime-sink-reachability', 'runtime-policy-violation']
    rule_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=5000)
    severity: Literal['critical', 'high', 'medium', 'low', 'info']
    confidence: Literal['confirmed', 'high', 'medium', 'low']
    source_kind: str = Field(min_length=1, max_length=100)
    sink_kind: str = Field(min_length=1, max_length=100)
    trace_id: str = Field(min_length=1, max_length=128)
    data_labels: list[str] = Field(default_factory=list, max_length=32)
    location: str = Field(default='', max_length=500)
    cwe_id: str = Field(default='', max_length=20)
    owasp_category: str = Field(default='', max_length=50)
    remediation: str = Field(default='', max_length=5000)
    method: str = Field(default='', max_length=10)
    parameter: str = Field(default='', max_length=200)
    file_path: str = Field(default='', max_length=500)
    line: int | None = Field(default=None, ge=1, le=10_000_000)
    function_name: str = Field(default='', max_length=200)


def _raise_iast_http(exc: Exception) -> None:
    if isinstance(exc, IASTConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, IASTAuthorizationError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, IASTError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


@router.post('/sessions')
async def create_iast_session(body: IASTSessionRequest, user=Depends(get_current_user)):
    try:
        result = await sync_to_async(start_iast_session, thread_sensitive=True)(
            project_id=body.project_id,
            asset_id=body.asset_id,
            scan_id=body.scan_id,
            authorization_id=body.authorization_id,
            actor_id=str(user.get('user_id')),
            provider_identity=body.provider_identity,
            instrumentation_mode=body.instrumentation_mode,
            idempotency_key=body.idempotency_key,
        )
    except Exception as exc:
        _raise_iast_http(exc)
    session = result.session
    return {
        'id': str(session.id),
        'organization_id': str(session.organization_id),
        'project_id': str(session.project_id),
        'asset_id': str(session.asset_id),
        'scan_id': str(session.scan_id),
        'authorization_id': str(session.authorization_decision_id),
        'target': session.target_snapshot,
        'provider_identity_sha256': session.provider_identity_sha256,
        'instrumentation_mode': session.instrumentation_mode,
        'policy_version': session.policy_version,
        'contract_fingerprint': session.contract_fingerprint,
        'request_fingerprint': session.request_fingerprint,
        'replayed': result.replayed,
    }


@router.post('/sessions/{session_id}/observations')
async def create_iast_observation(
    session_id: str,
    body: IASTObservationRequest,
    user=Depends(get_current_user),
):
    try:
        result = await sync_to_async(ingest_iast_observation, thread_sensitive=True)(
            session_id=session_id,
            actor_id=str(user.get('user_id')),
            **body.model_dump(),
        )
    except Exception as exc:
        _raise_iast_http(exc)
    observation = result.observation
    return {
        'id': str(observation.id),
        'session_id': str(observation.session_id),
        'finding_id': str(observation.finding_id),
        'evidence_id': str(observation.evidence_id),
        'qualification_id': str(observation.qualification_id),
        'observation_sha256': observation.observation_sha256,
        'request_fingerprint': observation.request_fingerprint,
        'severity': observation.severity,
        'confidence': observation.confidence,
        'replayed': result.replayed,
    }
