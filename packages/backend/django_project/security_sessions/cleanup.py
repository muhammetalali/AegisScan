from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone

from .models import ExecutionIdentity, SecurityTestSession
from .services import SessionAccessError, _append_evidence_locked
from users.models import User
from projects.authorization import get_project_authorization


def cleanup_session(*, session_id: Any, user_id: Any, reason: str = "") -> dict[str, Any]:
    user = User.objects.get(pk=user_id)
    with transaction.atomic():
        session = SecurityTestSession.objects.select_for_update().get(pk=session_id)
        if not get_project_authorization(session.project_id, user).can_update:
            raise SessionAccessError("project access denied")

        now = timezone.now()
        changed = []
        if not session.is_terminal:
            session.status = SecurityTestSession.Status.COMPLETED
            session.ended_at = now
            session.terminal_reason = reason.strip() or "cleanup requested"
            changed.extend(["status", "ended_at", "terminal_reason"])

        identity = ExecutionIdentity.objects.select_for_update().filter(session=session).first()
        if identity and identity.revoked_at is None:
            identity.revoked_at = now
            identity.save(update_fields=["revoked_at"])
            changed.append("identity.revoked_at")

        identity_active = bool(identity and identity.revoked_at is None and identity.expires_at > now)
        cleanup_status = SecurityTestSession.CleanupStatus.FAILED if identity_active else SecurityTestSession.CleanupStatus.VERIFIED
        session.cleanup_status = cleanup_status
        changed.append("cleanup_status")
        if changed:
            session.save(update_fields=[*changed, "updated_at"])

        _append_evidence_locked(
            session,
            event_type="cleanup.completed",
            action="cleanup_session",
            status="success" if cleanup_status == SecurityTestSession.CleanupStatus.VERIFIED else "failed",
            data={
                "identity_present": identity is not None,
                "identity_active_after_cleanup": identity_active,
                "changed": changed,
                "reason": reason.strip(),
            },
        )

    return {
        "session_id": str(session.id),
        "cleanup_status": session.cleanup_status,
        "identity_active_after_cleanup": identity_active,
        "verified": cleanup_status == SecurityTestSession.CleanupStatus.VERIFIED,
    }
