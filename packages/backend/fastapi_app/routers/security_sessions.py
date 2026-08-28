from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services import security_sessions as session_service
from ..security_sessions.integrity import verify_evidence_chain_by_id

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def _user_id(user: dict[str, Any]) -> Any:
    value = user.get("user_id") or user.get("id")
    if value is None:
        raise HTTPException(status_code=401, detail="Token has no user identity")
    return value


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, session_service.SessionAccessError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, session_service.SessionPolicyError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, KeyError):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=500, detail="Security session operation failed")


class SessionCreateRequest(BaseModel):
    project_id: UUID
    name: str = Field(min_length=3, max_length=200)
    authorization_id: str = Field(min_length=1, max_length=200)
    scope: dict[str, Any]
    capabilities: list[str] = Field(default_factory=list)
    ttl_minutes: int = Field(default=60, ge=5, le=480)
    environment: str = Field(default="lab", max_length=80)
    assessment_type: str = Field(default="security_validation", max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)
    baseline: dict[str, Any] = Field(default_factory=dict)
    authorization_evidence: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = Field(default=None, max_length=200)


class EvidenceCreateRequest(BaseModel):
    event_type: str = Field(min_length=2, max_length=100)
    capability: str = Field(default="", max_length=80)
    target: str = Field(default="", max_length=500)
    action: str = Field(default="", max_length=200)
    status: str = Field(default="observed", max_length=40)
    artifact_ref: str = Field(default="", max_length=500)
    data: dict[str, Any] = Field(default_factory=dict)


class SessionCloseRequest(BaseModel):
    status: Literal["completed", "failed", "revoked", "expired"] = "completed"
    reason: str = Field(default="", max_length=2000)


class CleanupVerifyRequest(BaseModel):
    status: Literal["verified", "partial", "failed"] = "verified"
    summary: dict[str, Any] = Field(default_factory=dict)


class RevokeIdentityRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


@router.post("/security-sessions", status_code=201)
async def create_security_session(payload: SessionCreateRequest, user: dict[str, Any] = Depends(current_user)):
    try:
        return await run_in_threadpool(
            session_service.create_session,
            user_id=_user_id(user), project_id=payload.project_id, name=payload.name,
            authorization_id=payload.authorization_id, scope=payload.scope, capabilities=payload.capabilities,
            ttl_minutes=payload.ttl_minutes, environment=payload.environment,
            assessment_type=payload.assessment_type, metadata=payload.metadata, baseline=payload.baseline,
            authorization_evidence=payload.authorization_evidence, approval_id=payload.approval_id,
        )
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/security-sessions/{session_id}")
async def get_security_session(session_id: UUID, user: dict[str, Any] = Depends(current_user)):
    try:
        return await run_in_threadpool(session_service.get_session_snapshot, session_id=session_id, user_id=_user_id(user))
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/security-sessions/{session_id}/evidence")
async def get_session_evidence(
    session_id: UUID,
    limit: int = Query(default=100, ge=1, le=500),
    user: dict[str, Any] = Depends(current_user),
):
    try:
        return await run_in_threadpool(session_service.list_evidence, session_id=session_id, user_id=_user_id(user), limit=limit)
    except Exception as exc:
        raise _translate(exc) from exc


@router.get("/security-sessions/{session_id}/evidence/integrity")
async def get_evidence_integrity(session_id: UUID, user: dict[str, Any] = Depends(current_user)):
    try:
        await run_in_threadpool(session_service.get_session_snapshot, session_id=session_id, user_id=_user_id(user))
        return await run_in_threadpool(verify_evidence_chain_by_id, session_id)
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/security-sessions/{session_id}/evidence", status_code=201)
async def append_session_evidence(
    session_id: UUID,
    payload: EvidenceCreateRequest,
    user: dict[str, Any] = Depends(current_user),
):
    try:
        return await run_in_threadpool(
            session_service.append_evidence,
            session_id=session_id, user_id=_user_id(user), event_type=payload.event_type,
            capability=payload.capability, target=payload.target, action=payload.action,
            status=payload.status, data=payload.data, artifact_ref=payload.artifact_ref,
        )
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/security-sessions/{session_id}/close")
async def close_security_session(
    session_id: UUID,
    payload: SessionCloseRequest,
    user: dict[str, Any] = Depends(current_user),
):
    try:
        return await run_in_threadpool(
            session_service.close_session,
            session_id=session_id, user_id=_user_id(user), status=payload.status, reason=payload.reason,
        )
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/security-sessions/{session_id}/identity/revoke")
async def revoke_security_identity(
    session_id: UUID,
    payload: RevokeIdentityRequest,
    user: dict[str, Any] = Depends(current_user),
):
    try:
        return await run_in_threadpool(
            session_service.revoke_identity,
            session_id=session_id, user_id=_user_id(user), reason=payload.reason,
        )
    except Exception as exc:
        raise _translate(exc) from exc


@router.post("/security-sessions/{session_id}/cleanup/verify")
async def verify_session_cleanup(
    session_id: UUID,
    payload: CleanupVerifyRequest,
    user: dict[str, Any] = Depends(current_user),
):
    try:
        return await run_in_threadpool(
            session_service.verify_cleanup,
            session_id=session_id, user_id=_user_id(user), status=payload.status, summary=payload.summary,
        )
    except Exception as exc:
        raise _translate(exc) from exc
