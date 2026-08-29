"""FastAPI-facing adapter for the canonical Django security-session service.

The security session domain is owned by Django because it persists identity,
authorization, evidence, and lifecycle state. FastAPI routers import this
adapter so the cross-service boundary remains explicit and stable.

The adapter intentionally re-exports the policy constants and validation/
redaction helpers used by FastAPI-facing tests and integration code. This
keeps the public FastAPI service boundary stable without duplicating domain
logic in the FastAPI layer.
"""

from django_project.security_sessions.services import (
    ALLOWED_CAPABILITIES,
    SessionAccessError,
    SessionPolicyError,
    _validate_capabilities,
    _validate_scope,
    append_evidence,
    close_session,
    create_session,
    get_session_snapshot,
    list_evidence,
    redact,
    revoke_identity,
    verify_cleanup,
)

__all__ = [
    "ALLOWED_CAPABILITIES",
    "SessionAccessError",
    "SessionPolicyError",
    "_validate_capabilities",
    "_validate_scope",
    "append_evidence",
    "close_session",
    "create_session",
    "get_session_snapshot",
    "list_evidence",
    "redact",
    "revoke_identity",
    "verify_cleanup",
]
