from __future__ import annotations

import logging
import time
from typing import Any

from audit.models import AuditLog
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

ACTION_MAP = {
    "auth.login": AuditLog.Action.LOGIN,
    "auth.login_2fa": AuditLog.Action.LOGIN_FAILED,
    "auth.logout": AuditLog.Action.LOGOUT,
    "auth.register": AuditLog.Action.USER_CREATE,
    "auth.password.change": AuditLog.Action.PASSWORD_CHANGE,
    "auth.password_reset.request": AuditLog.Action.PASSWORD_RESET,
    "auth.password_reset.confirm": AuditLog.Action.PASSWORD_RESET,
    "auth.email_verification": AuditLog.Action.USER_UPDATE,
    "auth.email_verification.resend": AuditLog.Action.USER_UPDATE,
    "auth.2fa.enable.begin": AuditLog.Action.TWO_FACTOR_ENABLE,
    "auth.2fa.enable": AuditLog.Action.TWO_FACTOR_ENABLE,
    "auth.2fa.disable": AuditLog.Action.TWO_FACTOR_DISABLE,
    "user.profile.update": AuditLog.Action.USER_UPDATE,
    "user.activate": AuditLog.Action.USER_UPDATE,
    "user.deactivate": AuditLog.Action.USER_UPDATE,
    "api_key.create": AuditLog.Action.API_KEY_CREATE,
    "api_key.revoke": AuditLog.Action.API_KEY_REVOKE,
    "session.revoke": AuditLog.Action.LOGOUT,
    "session.revoke_all_others": AuditLog.Action.LOGOUT,
    "team.create": AuditLog.Action.USER_CREATE,
    "team.member.add": AuditLog.Action.USER_UPDATE,
    "team.member.role_update": AuditLog.Action.USER_ROLE_CHANGE,
    "team.member.remove": AuditLog.Action.USER_DELETE,
    "auth.login.legacy": AuditLog.Action.LOGIN,
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def record_user_audit(*, request, action: str, result: str, user=None, resource_type: str = "User",
                      resource_id: str = "", changes: dict[str, Any] | None = None,
                      metadata: dict[str, Any] | None = None, error_message: str = "", start: float | None = None):
    """Record security-relevant user activity without persisting credentials or bearer tokens."""
    canonical_action = ACTION_MAP.get(action)
    if canonical_action is None:
        raise ValueError(f"Unsupported user audit action: {action}")
    try:
        remote = request.META.get("REMOTE_ADDR") or "0.0.0.0"
        return append_audit(
            action=canonical_action,
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
