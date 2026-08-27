from __future__ import annotations

from typing import Any

from django.db import transaction

from .models import AuditLog, AuditChainState


GENESIS_HASH = "0" * 64


def append_audit(*, action: str, ip_address: str, user=None, result: str = AuditLog.Result.SUCCESS,
                 resource_type: str = "", resource_id: str = "", resource_repr: str = "",
                 changes: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None,
                 user_agent: str = "", location: str = "", session_id: str = "",
                 error_message: str = "", duration_ms: int = 0, request_id=None) -> AuditLog:
    """Append one audit entry while serializing every writer on a persistent chain-tail row."""
    with transaction.atomic():
        state, _ = AuditChainState.objects.get_or_create(
            id=1,
            defaults={"last_sequence": 0, "last_hash": GENESIS_HASH},
        )
        state = AuditChainState.objects.select_for_update().get(pk=state.pk)

        sequence = state.last_sequence + 1
        previous_hash = state.last_hash
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

        state.last_sequence = sequence
        state.last_hash = entry.entry_hash
        state.save(update_fields=["last_sequence", "last_hash", "updated_at"])
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

    state = AuditChainState.objects.filter(pk=1).first()
    if state is None:
        return expected_sequence == 1
    return state.last_sequence == expected_sequence - 1 and state.last_hash == previous
