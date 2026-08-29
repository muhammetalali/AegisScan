"""FastAPI-facing adapter for the canonical Django security-session service.

The security session domain is owned by Django because it persists identity,
authorization, evidence, and lifecycle state. FastAPI routers import this
adapter so the cross-service boundary remains explicit and stable.
"""

from django_project.security_sessions.services import (
    SessionAccessError,
    SessionPolicyError,
    append_evidence,
    close_session,
    create_session,
    get_session_snapshot,
    list_evidence,
    revoke_identity,
    verify_cleanup,
)

__all__ = [
    "SessionAccessError",
    "SessionPolicyError",
    "append_evidence",
    "close_session",
    "create_session",
    "get_session_snapshot",
    "list_evidence",
    "revoke_identity",
    "verify_cleanup",
]
