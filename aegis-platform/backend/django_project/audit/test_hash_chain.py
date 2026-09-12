import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from concurrent.futures import ThreadPoolExecutor

from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit, verify_audit_chain


def _append(resource_id: str) -> AuditLog:
    return append_audit(
        action=AuditLog.Action.API_REQUEST,
        result=AuditLog.Result.SUCCESS,
        resource_type='test',
        resource_id=resource_id,
        resource_repr=f'Test {resource_id}',
        ip_address='127.0.0.1',
    )


@pytest.mark.django_db(transaction=True)
def test_audit_entries_are_sequenced_hash_linked_and_verifiable():
    first = _append('first')
    second = _append('second')

    assert first.chain_index == 1
    assert first.previous_hash == ''
    assert second.chain_index == 2
    assert second.previous_hash == first.entry_hash
    assert verify_audit_chain() == (True, second.entry_hash)


@pytest.mark.django_db(transaction=True)
def test_audit_entries_reject_model_queryset_mutation_and_deletion():
    entry = _append('immutable')
    entry.resource_repr = 'tampered'

    with pytest.raises(ValidationError, match='append_audit'):
        entry.save()
    with pytest.raises(ValidationError, match='append-only'):
        AuditLog.objects.filter(pk=entry.pk).update(resource_repr='tampered')
    with pytest.raises(ValidationError, match='append-only'):
        AuditLog.objects.filter(pk=entry.pk).delete()
    with pytest.raises(ValidationError, match='append-only'):
        entry.delete()
    with pytest.raises(ValidationError, match='append_audit'):
        AuditLog.objects.bulk_create([AuditLog(resource_type='invalid')])

    entry.refresh_from_db()
    assert entry.resource_repr == 'Test immutable'
    assert verify_audit_chain()[0] is True


@pytest.mark.django_db(transaction=True)
def test_postgresql_concurrent_appends_remain_one_linear_chain():
    if connection.vendor != 'postgresql':
        pytest.skip('PostgreSQL advisory-lock proof')

    def append_from_worker(number: int) -> int:
        close_old_connections()
        try:
            return _append(f'concurrent-{number}').chain_index
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as pool:
        indexes = list(pool.map(append_from_worker, range(16)))

    assert sorted(indexes) == list(range(1, 17))
    assert verify_audit_chain()[0] is True
