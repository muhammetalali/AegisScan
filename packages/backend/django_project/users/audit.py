from __future__ import annotations

import logging
import time
from typing import Any

from audit.services import append_audit

logger = logging.getLogger(__name__)


SENSITIVE_KEYS = {
    "password",
    "old_password",
    "new_password",
    "password_reset_token",
    "email_verification_token",
    "token",
    "access",
    "refresh",
    "otp",
    "code",
    "two_factor_secret",
    "secret",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else _sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def record_user_audit(*, request, action: str, result: str, user=None, resource_type: str = "User",
                      resource_id: str = "", changes: dict[str, Any] | None = None,
                      metadata: dict[str, Any] | None = None, error_message: str = "", start: float | None = None):
    """Record security-relevant user activity without persisting credentials or bearer tokens."""
    try:
        remote = request.META.get("REMOTE_ADDR") or "0.0.0.0"
        return append_audit(
            action=action,
            ip_address=remote,
            user=user,
            result=result,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else "",
            resource_repr=str(user) if user is not None else "",
            changes=_sanitize(changes or {}),
            metadata=_sanitize(metadata or {}),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            session_id=request.session.session_key or "",
            error_message=error_message[:500],
            duration_ms=max(0, int((time.monotonic() - start) * 1000)) if start is not None else 0,
        )
    except Exception:
        logger.exception("Failed to persist user security audit event: %s", action)
        return None
