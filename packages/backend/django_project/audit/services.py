from __future__ import annotations

from typing import Any

from django.db import transaction

from .models import AuditLog


GENESIS_HASH = "0" * 64


def append_audit(*, action: str, ip_address: str, user=None, result: str = AuditLog.Result.SUCCESS,
                 resource_type: str = "", resource_id: str = "", resource_repr: str = "",
                 changes: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None,
                 user_agent: str = "", location: str = "", session_id: str = "",
                 error_message: str = "", duration_ms: int = 0, request_id=None) -> AuditLog:
    """Append one audit entry while serializing writers on the chain tail."""
    with transaction.atomic():
        last = AuditLog.objects.select_for_update().order_by("-sequence").first()
        previous_hash = last.entry_hash if last else GENESIS_HASH
        sequence = (last.sequence + 1) if last else 1
        entry = AuditLog(
            user=user, action=action, result=result, resource_type=resource_type,
            resource_id=resource_id, resource_repr=resource_repr, changes=changes or {},
            metadata=metadata or {}, ip_address=ip_address, user_agent=user_agent,
            location=location, session_id=session_id, error_message=error_message,
            duration_ms=duration_ms, sequence=sequence, previous_hash=previous_hash,
        )
        if request_id is not None:
            entry.request_id = request_id
        entry.entry_hash = AuditLog.calculate_hash(entry, previous_hash)
        entry.save(force_insert=True)
        return entry


def verify_audit_chain() -> bool:
    previous = GENESIS_HASH
    expected_sequence = 1
    for entry in AuditLog.objects.order_by("sequence").iterator():
        if entry.sequence != expected_sequence or entry.previous_hash != previous:
            return False
        if entry.entry_hash != AuditLog.calculate_hash(entry, previous):
            return False
        previous = entry.entry_hash
        expected_sequence += 1
    return True
