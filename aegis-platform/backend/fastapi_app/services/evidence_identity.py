from __future__ import annotations

from uuid import UUID, uuid5


# Stable application namespace. Evidence identity is derived from the durable
# operation, not from a Celery delivery or worker process.
EVIDENCE_NAMESPACE = UUID('d2c60c4e-8f0e-4e63-9602-acdeaf3a76ec')


def evidence_id(
    operation_kind: str,
    operation_id: str,
    source: str,
    evidence_type: str,
    finding_id: str | None = None,
) -> UUID:
    parts = (
        operation_kind.strip().lower(),
        str(operation_id).strip().lower(),
        source.strip().lower(),
        evidence_type.strip().lower(),
        str(finding_id or '').strip().lower(),
    )
    if not all(parts[:4]):
        raise ValueError('Evidence identity requires operation, source and type')
    return uuid5(EVIDENCE_NAMESPACE, ':'.join(parts))
