from __future__ import annotations

from typing import Any

from django.db import transaction

from .models import EvidenceRecord, SecurityTestSession
from .services import _canonical, _sha256, redact


def verify_evidence_chain(session: SecurityTestSession) -> dict[str, Any]:
    records = list(EvidenceRecord.objects.filter(session=session).order_by("sequence"))
    previous_hash = ""
    first_invalid: int | None = None

    for record in records:
        content = {
            "event_type": record.event_type,
            "capability": record.capability,
            "target": record.target,
            "action": record.action,
            "status": record.status,
            "artifact_ref": record.artifact_ref,
            "data": redact(record.data),
        }
        content_hash = _sha256(_canonical(content))
        event_hash = _sha256(
            _canonical(
                {
                    "sequence": record.sequence,
                    "previous_hash": previous_hash,
                    "content_hash": content_hash,
                }
            )
        )
        if record.previous_hash != previous_hash or record.content_hash != content_hash or record.event_hash != event_hash:
            first_invalid = record.sequence
            break
        previous_hash = record.event_hash

    return {
        "valid": first_invalid is None,
        "record_count": len(records),
        "head_hash": previous_hash if first_invalid is None else "",
        "first_invalid_sequence": first_invalid,
    }


def verify_evidence_chain_by_id(session_id: Any) -> dict[str, Any]:
    with transaction.atomic():
        session = SecurityTestSession.objects.get(pk=session_id)
        return verify_evidence_chain(session)
