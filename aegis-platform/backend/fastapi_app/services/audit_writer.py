from __future__ import annotations

from typing import Any, Mapping
from uuid import UUID

from django_project.audit.models import AuditLog
from django_project.users.models import User


def add_audit_entry(
    *,
    user: str | int | None,
    action: str,
    target: str | None = None,
    project: str | None = None,
    result: str = AuditLog.Result.SUCCESS,
    resource_type: str = "",
    resource_repr: str = "",
    changes: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    error_message: str = "",
    duration_ms: int = 0,
    request: Any | None = None,
) -> AuditLog:
    actor = User.objects.filter(pk=user).first() if user is not None else None

    client = getattr(request, "client", None) if request is not None else None
    ip_address = getattr(client, "host", None) or "0.0.0.0"
    user_agent = ""
    session_id = ""
    request_id = None

    if request is not None:
        user_agent = request.headers.get("user-agent", "")[:5000]
        session_id = request.headers.get("x-session-id", "")[:100]
        raw_request_id = request.headers.get("x-request-id")
        if raw_request_id:
            try:
                request_id = UUID(raw_request_id)
            except ValueError:
                request_id = None

    entry_metadata = dict(metadata or {})
    entry_metadata.setdefault("source", "fastapi")
    if project not in (None, "", "—"):
        entry_metadata.setdefault("project_id", str(project))
    if user is not None and actor is None:
        entry_metadata.setdefault("actor_identifier", str(user))

    return AuditLog.objects.create(
        user=actor,
        action=action,
        result=result,
        resource_type=resource_type,
        resource_id=str(target or ""),
        resource_repr=resource_repr,
        changes=dict(changes or {}),
        metadata=entry_metadata,
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=session_id,
        request_id=request_id or AuditLog._meta.get_field("request_id").default(),
        error_message=error_message,
        duration_ms=max(0, int(duration_ms)),
    )
