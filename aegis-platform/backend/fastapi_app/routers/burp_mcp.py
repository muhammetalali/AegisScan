from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..core.dependencies import get_current_user
from ..services.burp_mcp_gateway import (
    BurpMCPAuthorizationError,
    BurpMCPConflict,
    BurpMCPError,
    BurpMCPProviderError,
    BurpMCPRateLimit,
    invoke_burp_mcp,
    start_burp_mcp_session,
)


router = APIRouter()


class BurpMCPSessionIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    project_id: UUID
    asset_id: UUID
    scan_id: UUID
    authorization_id: UUID
    provider_name: str = Field(min_length=1, max_length=180)
    provider_version: str = Field(min_length=1, max_length=120)
    requested_operations: list[str] = Field(min_length=1, max_length=4)
    idempotency_key: str = Field(min_length=1, max_length=128)
    credential_ref: UUID | None = None
    max_invocations: int = Field(default=20, ge=1, le=100)
    rate_limit_per_minute: int = Field(default=10, ge=1, le=60)
    ttl_seconds: int = Field(default=1800, ge=60, le=3600)


class BurpMCPSessionOut(BaseModel):
    id: str
    project_id: str
    asset_id: str
    scan_id: str
    authorization_id: str
    provider_approval_id: str
    provider_identity_sha256: str
    target: str
    allowed_tools: dict[str, str]
    max_invocations: int
    rate_limit_per_minute: int
    expires_at: str
    contract_fingerprint: str
    replayed: bool


class BurpMCPInvokeIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    operation: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=128)


class BurpMCPInvocationOut(BaseModel):
    id: str
    session_id: str
    operation: str
    provider_tool_name: str
    invocation_sequence: int
    evidence_id: str
    qualification_id: str
    request_fingerprint: str
    arguments_sha256: str
    provider_result_sha256: str
    evidence_sha256: str
    result_summary: dict[str, Any]
    replayed: bool


def _actor_id(user: dict[str, Any]) -> str:
    value = user.get('user_id') or user.get('id')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user.')
    return str(value)


def _raise_gateway_error(exc: Exception) -> None:
    if isinstance(exc, BurpMCPRateLimit):
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    if isinstance(exc, BurpMCPConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, BurpMCPAuthorizationError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, BurpMCPProviderError):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, BurpMCPError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


@router.post('/sessions', response_model=BurpMCPSessionOut)
async def create_burp_mcp_session(payload: BurpMCPSessionIn, user=Depends(get_current_user)):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(start_burp_mcp_session)(
            project_id=str(payload.project_id),
            asset_id=str(payload.asset_id),
            scan_id=str(payload.scan_id),
            authorization_id=str(payload.authorization_id),
            actor_id=actor_id,
            provider_name=payload.provider_name,
            provider_version=payload.provider_version,
            requested_operations=payload.requested_operations,
            idempotency_key=payload.idempotency_key,
            credential_ref=str(payload.credential_ref) if payload.credential_ref else None,
            max_invocations=payload.max_invocations,
            rate_limit_per_minute=payload.rate_limit_per_minute,
            ttl_seconds=payload.ttl_seconds,
        )
    except Exception as exc:
        _raise_gateway_error(exc)
        raise

    session = result.session
    return BurpMCPSessionOut(
        id=str(session.id),
        project_id=str(session.project_id),
        asset_id=str(session.asset_id),
        scan_id=str(session.scan_id),
        authorization_id=str(session.authorization_decision_id),
        provider_approval_id=str(session.provider_approval_id),
        provider_identity_sha256=session.provider_identity_sha256,
        target=session.target_snapshot,
        allowed_tools=dict(session.allowed_tools or {}),
        max_invocations=int(session.max_invocations),
        rate_limit_per_minute=int(session.rate_limit_per_minute),
        expires_at=session.expires_at.isoformat(),
        contract_fingerprint=session.contract_fingerprint,
        replayed=result.replayed,
    )


@router.post('/sessions/{session_id}/invoke', response_model=BurpMCPInvocationOut)
async def invoke_burp_mcp_tool(session_id: UUID, payload: BurpMCPInvokeIn, user=Depends(get_current_user)):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(invoke_burp_mcp)(
            session_id=str(session_id),
            actor_id=actor_id,
            operation=payload.operation,
            arguments=payload.arguments,
            idempotency_key=payload.idempotency_key,
        )
    except Exception as exc:
        _raise_gateway_error(exc)
        raise

    invocation = result.invocation
    return BurpMCPInvocationOut(
        id=str(invocation.id),
        session_id=str(invocation.session_id),
        operation=invocation.operation,
        provider_tool_name=invocation.provider_tool_name,
        invocation_sequence=int(invocation.invocation_sequence),
        evidence_id=str(invocation.evidence_id),
        qualification_id=str(invocation.qualification_id),
        request_fingerprint=invocation.request_fingerprint,
        arguments_sha256=invocation.arguments_sha256,
        provider_result_sha256=invocation.provider_result_sha256,
        evidence_sha256=invocation.evidence_sha256,
        result_summary=dict(invocation.result_summary or {}),
        replayed=result.replayed,
    )
