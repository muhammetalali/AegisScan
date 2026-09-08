from __future__ import annotations

import threading
import ipaddress
from contextlib import contextmanager
from typing import Any

from django.db import connection, transaction

from .models import AuditLog


_CHAIN_LOCK_KEY = 0x4145474953415544
_LOCAL_CHAIN_LOCK = threading.Lock()


def client_ip_from_request(request: Any) -> str:
    meta = getattr(request, 'META', {})
    forwarded = meta.get('HTTP_X_FORWARDED_FOR', '')
    candidates = [value.strip() for value in forwarded.split(',') if value.strip()]
    candidates.append(meta.get('HTTP_X_REAL_IP', '').strip())
    candidates.append(meta.get('REMOTE_ADDR', '').strip())
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return '127.0.0.1'


@contextmanager
def _serialize_chain_append():
    if connection.vendor == 'postgresql':
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [_CHAIN_LOCK_KEY])
        yield
        return
    with _LOCAL_CHAIN_LOCK:
        yield


@transaction.atomic
def append_audit(**values: Any) -> AuditLog:
    """Append one immutable, hash-linked audit record under a database lock."""
    with _serialize_chain_append():
        previous = AuditLog.objects.order_by('-chain_index').only('chain_index', 'entry_hash').first()
        previous_hash = previous.entry_hash if previous else ''
        metadata = dict(values.pop('metadata', {}) or {})
        user = values.get('user')
        user_id = values.get('user_id') or getattr(user, 'pk', None)
        if user_id is not None:
            metadata.setdefault('actor_id_snapshot', str(user_id))
        impersonated = values.get('impersonated_by')
        impersonated_id = values.get('impersonated_by_id') or getattr(impersonated, 'pk', None)
        if impersonated_id is not None:
            metadata.setdefault('impersonated_by_id_snapshot', str(impersonated_id))
        entry = AuditLog(
            chain_index=(previous.chain_index + 1) if previous else 1,
            previous_hash=previous_hash,
            metadata=metadata,
            **values,
        )
        entry.entry_hash = AuditLog.calculate_hash(entry, previous_hash)
        entry.save(_append_only=True, force_insert=True)
        return entry


def verify_audit_chain() -> tuple[bool, str]:
    previous_hash = ''
    expected_index = 1
    for entry in AuditLog.objects.order_by('chain_index').iterator():
        if entry.chain_index != expected_index:
            return False, f'chain index gap at {entry.id}'
        if entry.previous_hash != previous_hash:
            return False, f'previous hash mismatch at {entry.id}'
        expected = AuditLog.calculate_hash(entry, previous_hash)
        if entry.entry_hash != expected:
            return False, f'entry hash mismatch at {entry.id}'
        previous_hash = entry.entry_hash
        expected_index += 1
    return True, previous_hash
