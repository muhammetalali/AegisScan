from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from projects.authorization import get_project_authorization
from projects.models import Project
from users.models import User

from .models import EvidenceRecord, ExecutionIdentity, SecurityTestSession


ALLOWED_CAPABILITIES = frozenset(
    {
        "discover_assets",
        "passive_validate",
        "active_validate",
        "evidence_collect",
        "remediation_propose",
        "remediation_execute",
        "remediation_verify",
        "interactive_session",
        "privileged_validation",
    }
)
HIGH_RISK_CAPABILITIES = frozenset({"interactive_session", "privileged_validation"})
MAX_TTL_MINUTES = 8 * 60
SENSITIVE_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "password",
        "secret",
        "authorization",
        "cookie",
        "set-cookie",
        "client_secret",
    }
)


class SessionPolicyError(ValueError):
    pass


class SessionAccessError(PermissionError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def _validate_scope(scope: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scope, dict):
        raise SessionPolicyError("scope must be an object")
    targets = scope.get("targets") or []
    asset_ids = scope.get("asset_ids") or []
    if not isinstance(targets, list) or not isinstance(asset_ids, list):
        raise SessionPolicyError("scope.targets and scope.asset_ids must be arrays")
    if not targets and not asset_ids:
        raise SessionPolicyError("scope must contain at least one target or asset_id")
    if any(not isinstance(item, (str, int)) or not str(item).strip() for item in [*targets, *asset_ids]):
        raise SessionPolicyError("scope entries must be non-empty strings or integers")
    normalized = {**scope, "targets": [str(x).strip() for x in targets], "asset_ids": [str(x).strip() for x in asset_ids]}
    normalized["boundary"] = normalized.get("boundary") or "explicit"
    return normalized


def _validate_capabilities(capabilities: list[str], approval_id: str | None, user: User) -> list[str]:
    requested = [str(x).strip() for x in capabilities if str(x).strip()]
    unknown = sorted(set(requested) - ALLOWED_CAPABILITIES)
    if unknown:
        raise SessionPolicyError(f"unsupported capabilities: {', '.join(unknown)}")
    if HIGH_RISK_CAPABILITIES.intersection(requested):
        if not approval_id:
            raise SessionPolicyError("interactive/privileged capabilities require approval_id")
        if not user.is_staff and not user.is_superuser:
            raise SessionAccessError("interactive/privileged capabilities require staff authorization")
    return list(dict.fromkeys(requested))


def _assert_project_access(project_id: Any, user: User, *, write: bool) -> Project:
    project = Project.objects.get(pk=project_id)
    auth = get_project_authorization(project.id, user)
    allowed = auth.can_update if write else auth.can_read
    if not allowed:
        raise SessionAccessError("project access denied")
    return project


def _issue_identity_locked(session: SecurityTestSession) -> tuple[ExecutionIdentity, str]:
    raw_token = secrets.token_urlsafe(32)
    identity = ExecutionIdentity.objects.create(
        session=session,
        identity_ref=f"exec-{uuid.uuid4().hex}",
        token_prefix=raw_token[:12],
        token_hash=_sha256(raw_token.encode()),
        issued_at=timezone.now(),
        expires_at=session.expires_at,
        capabilities=session.capabilities,
        claims={
            "session_id": str(session.id),
            "project_id": str(session.project_id),
            "authorization_id": session.authorization_id,
            "environment": session.environment,
        },
    )
    return identity, raw_token


def _append_evidence_locked(
    session: SecurityTestSession,
    *,
    event_type: str,
    capability: str = "",
    target: str = "",
    action: str = "",
    status: str = "observed",
    data: dict[str, Any] | None = None,
    artifact_ref: str = "",
) -> EvidenceRecord:
    last = EvidenceRecord.objects.filter(session=session).order_by("-sequence").first()
    sequence = (last.sequence + 1) if last else 1
    previous_hash = last.event_hash if last else ""
    safe_data = redact(data or {})
    content = {
        "event_type": event_type,
        "capability": capability,
        "target": target,
        "action": action,
        "status": status,
        "artifact_ref": artifact_ref,
        "data": safe_data,
    }
    content_hash = _sha256(_canonical(content))
    event_hash = _sha256(_canonical({"sequence": sequence, "previous_hash": previous_hash, "content_hash": content_hash}))
    return EvidenceRecord.objects.create(
        session=session,
        sequence=sequence,
        event_type=event_type,
        capability=capability,
        target=target,
        action=action,
        status=status,
        artifact_ref=artifact_ref,
        data=safe_data,
        content_hash=content_hash,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )


def create_session(
    *,
    user_id: Any,
    project_id: Any,
    name: str,
    authorization_id: str,
    scope: dict[str, Any],
    capabilities: list[str],
    ttl_minutes: int = 60,
    environment: str = "lab",
    assessment_type: str = "security_validation",
    metadata: dict[str, Any] | None = None,
    baseline: dict[str, Any] | None = None,
    authorization_evidence: dict[str, Any] | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    project = _assert_project_access(project_id, user, write=True)
    if not authorization_id.strip():
        raise SessionPolicyError("authorization_id is required")
    if not name.strip():
        raise SessionPolicyError("name is required")
    if ttl_minutes < 5 or ttl_minutes > MAX_TTL_MINUTES:
        raise SessionPolicyError(f"ttl_minutes must be between 5 and {MAX_TTL_MINUTES}")
    normalized_scope = _validate_scope(scope)
    normalized_capabilities = _validate_capabilities(capabilities, approval_id, user)
    now = timezone.now()
    expires_at = now + timedelta(minutes=ttl_minutes)

    with transaction.atomic():
        session = SecurityTestSession.objects.create(
            project=project,
            initiated_by=user,
            name=name.strip(),
            assessment_type=assessment_type.strip() or "security_validation",
            authorization_id=authorization_id.strip(),
            environment=environment.strip() or "lab",
            status=SecurityTestSession.Status.ACTIVE,
            scope=normalized_scope,
            capabilities=normalized_capabilities,
            authorization_evidence=redact(authorization_evidence or ({"approval_id": approval_id} if approval_id else {})),
            baseline=redact(baseline or {}),
            metadata=redact(metadata or {}),
            started_at=now,
            expires_at=expires_at,
        )
        identity, raw_token = _issue_identity_locked(session)
        _append_evidence_locked(
            session,
            event_type="session.created",
            action="create_session",
            status="success",
            data={
                "authorization_id": session.authorization_id,
                "capabilities": normalized_capabilities,
                "scope": normalized_scope,
                "environment": session.environment,
                "approval_id": approval_id,
            },
        )
        _append_evidence_locked(
            session,
            event_type="identity.issued",
            action="issue_execution_identity",
            status="success",
            data={"identity_ref": identity.identity_ref, "expires_at": identity.expires_at.isoformat()},
        )
    return {"session": serialize_session(session), "execution_credential": raw_token}


def authenticate_execution_identity(token: str) -> tuple[ExecutionIdentity, SecurityTestSession]:
    token_hash = _sha256(token.encode())
    identity = ExecutionIdentity.objects.select_related("session").filter(token_hash=token_hash).first()
    if identity is None or not identity.active:
        raise SessionAccessError("invalid or expired execution identity")
    session = identity.session
    if session.is_expired and not session.is_terminal:
        session.status = SecurityTestSession.Status.EXPIRED
        session.ended_at = timezone.now()
        session.terminal_reason = "execution identity expired"
        session.save(update_fields=["status", "ended_at", "terminal_reason", "updated_at"])
        raise SessionAccessError("security test session expired")
    if session.status != SecurityTestSession.Status.ACTIVE:
        raise SessionAccessError("security test session is not active")
    identity.last_seen_at = timezone.now()
    identity.save(update_fields=["last_seen_at"])
    return identity, session


def append_evidence(
    *,
    session_id: Any,
    user_id: Any,
    event_type: str,
    capability: str = "",
    target: str = "",
    action: str = "",
    status: str = "observed",
    data: dict[str, Any] | None = None,
    artifact_ref: str = "",
) -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    with transaction.atomic():
        session = SecurityTestSession.objects.select_for_update().select_related("project").get(pk=session_id)
        if not get_project_authorization(session.project_id, user).can_update:
            raise SessionAccessError("project access denied")
        if session.status != SecurityTestSession.Status.ACTIVE:
            raise SessionPolicyError("evidence can only be appended to an active session")
        if capability and capability not in session.capabilities:
            raise SessionPolicyError("capability is not granted to this session")
        record = _append_evidence_locked(
            session,
            event_type=event_type,
            capability=capability,
            target=target,
            action=action,
            status=status,
            data=data,
            artifact_ref=artifact_ref,
        )
    return serialize_evidence(record)


def close_session(*, session_id: Any, user_id: Any, status: str = "completed", reason: str = "") -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    allowed_statuses = {
        SecurityTestSession.Status.COMPLETED,
        SecurityTestSession.Status.FAILED,
        SecurityTestSession.Status.REVOKED,
        SecurityTestSession.Status.EXPIRED,
    }
    if status not in allowed_statuses:
        raise SessionPolicyError("invalid terminal status")
    with transaction.atomic():
        session = SecurityTestSession.objects.select_for_update().select_related("project").get(pk=session_id)
        if not get_project_authorization(session.project_id, user).can_update:
            raise SessionAccessError("project access denied")
        if session.is_terminal:
            return serialize_session(session)
        session.status = status
        session.ended_at = timezone.now()
        session.terminal_reason = reason.strip()
        session.save(update_fields=["status", "ended_at", "terminal_reason", "updated_at"])
        if hasattr(session, "execution_identity"):
            session.execution_identity.revoked_at = timezone.now()
            session.execution_identity.save(update_fields=["revoked_at"])
        _append_evidence_locked(
            session,
            event_type="session.closed",
            action="close_session",
            status="success" if status == "completed" else status,
            data={"terminal_reason": session.terminal_reason},
        )
    return serialize_session(session)


def revoke_identity(*, session_id: Any, user_id: Any, reason: str = "") -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    with transaction.atomic():
        session = SecurityTestSession.objects.select_for_update().select_related("project").get(pk=session_id)
        if not get_project_authorization(session.project_id, user).can_update:
            raise SessionAccessError("project access denied")
        identity = ExecutionIdentity.objects.select_for_update().get(session=session)
        identity.revoked_at = timezone.now()
        identity.save(update_fields=["revoked_at"])
        if not session.is_terminal:
            session.status = SecurityTestSession.Status.REVOKED
            session.ended_at = timezone.now()
            session.terminal_reason = reason.strip() or "execution identity revoked"
            session.save(update_fields=["status", "ended_at", "terminal_reason", "updated_at"])
        _append_evidence_locked(
            session,
            event_type="identity.revoked",
            action="revoke_execution_identity",
            status="success",
            data={"reason": reason.strip()},
        )
    return serialize_session(session)


def verify_cleanup(*, session_id: Any, user_id: Any, status: str = "verified", summary: dict[str, Any] | None = None) -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    if status not in {SecurityTestSession.CleanupStatus.VERIFIED, SecurityTestSession.CleanupStatus.PARTIAL, SecurityTestSession.CleanupStatus.FAILED}:
        raise SessionPolicyError("invalid cleanup status")
    with transaction.atomic():
        session = SecurityTestSession.objects.select_for_update().select_related("project").get(pk=session_id)
        if not get_project_authorization(session.project_id, user).can_update:
            raise SessionAccessError("project access denied")
        if not session.is_terminal:
            raise SessionPolicyError("cleanup verification requires a terminal session")
        session.cleanup_status = status
        session.save(update_fields=["cleanup_status", "updated_at"])
        _append_evidence_locked(
            session,
            event_type="cleanup.verified",
            action="verify_cleanup",
            status=status,
            data=summary or {},
        )
    return serialize_session(session)


def get_session_snapshot(*, session_id: Any, user_id: Any) -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    session = SecurityTestSession.objects.select_related("project", "initiated_by").get(pk=session_id)
    if not get_project_authorization(session.project_id, user).can_read:
        raise SessionAccessError("project access denied")
    return serialize_session(session, include_identity=True)


def list_evidence(*, session_id: Any, user_id: Any, limit: int = 100) -> list[dict[str, Any]]:
    user = User.objects.get(pk=user_id)
    session = SecurityTestSession.objects.get(pk=session_id)
    if not get_project_authorization(session.project_id, user).can_read:
        raise SessionAccessError("project access denied")
    records = EvidenceRecord.objects.filter(session=session).order_by("sequence")[: max(1, min(limit, 500))]
    return [serialize_evidence(record) for record in records]


def serialize_evidence(record: EvidenceRecord) -> dict[str, Any]:
    return {
        "id": str(record.id),
        "sequence": record.sequence,
        "event_type": record.event_type,
        "capability": record.capability,
        "target": record.target,
        "action": record.action,
        "status": record.status,
        "artifact_ref": record.artifact_ref,
        "data": record.data,
        "content_hash": record.content_hash,
        "previous_hash": record.previous_hash,
        "event_hash": record.event_hash,
        "created_at": record.created_at.isoformat(),
    }


def serialize_session(session: SecurityTestSession, *, include_identity: bool = False) -> dict[str, Any]:
    payload = {
        "id": str(session.id),
        "project_id": str(session.project_id),
        "initiated_by": str(session.initiated_by_id),
        "name": session.name,
        "assessment_type": session.assessment_type,
        "authorization_id": session.authorization_id,
        "environment": session.environment,
        "status": session.status,
        "scope": session.scope,
        "capabilities": session.capabilities,
        "authorization_evidence": session.authorization_evidence,
        "baseline": session.baseline,
        "metadata": session.metadata,
        "terminal_reason": session.terminal_reason,
        "cleanup_status": session.cleanup_status,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "expires_at": session.expires_at.isoformat(),
        "ended_at": session.ended_at.isoformat() if session.ended_at else None,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
        "evidence_count": session.evidence_records.count(),
    }
    if include_identity:
        identity = getattr(session, "execution_identity", None)
        payload["execution_identity"] = (
            {
                "identity_ref": identity.identity_ref,
                "token_prefix": identity.token_prefix,
                "issued_at": identity.issued_at.isoformat(),
                "expires_at": identity.expires_at.isoformat(),
                "revoked_at": identity.revoked_at.isoformat() if identity.revoked_at else None,
                "last_seen_at": identity.last_seen_at.isoformat() if identity.last_seen_at else None,
                "capabilities": identity.capabilities,
                "active": identity.active,
            }
            if identity
            else None
        )
    return payload
