from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from django.test import TransactionTestCase

from .models import AuditLog, AuditChainState
from .services import GENESIS_HASH, append_audit, verify_audit_chain


class AuditChainTests(TransactionTestCase):
    reset_sequences = True

    def append(self, action=AuditLog.Action.LOGIN):
        return append_audit(action=action, ip_address='127.0.0.1', metadata={'test': True})

    def test_append_and_persist(self):
        first = self.append()
        second = self.append(AuditLog.Action.LOGOUT)
        state = AuditChainState.objects.get(pk=1)
        self.assertEqual(first.sequence, 1)
        self.assertEqual(first.previous_hash, GENESIS_HASH)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertEqual(state.last_sequence, 2)
        self.assertEqual(state.last_hash, second.entry_hash)
        self.assertTrue(verify_audit_chain())

    def test_verify_detects_tampering(self):
        entry = self.append()
        entry.metadata = {'tampered': True}
        entry.save(update_fields=['metadata'])
        self.assertFalse(verify_audit_chain())

    def test_verify_detects_broken_link(self):
        first = self.append()
        second = self.append(AuditLog.Action.LOGOUT)
        second.previous_hash = GENESIS_HASH
        second.save(update_fields=['previous_hash'])
        self.assertFalse(verify_audit_chain())

    def test_concurrent_append_has_unique_ordered_chain(self):
        def write(i):
            return append_audit(
                action=AuditLog.Action.LOGIN,
                ip_address='127.0.0.1',
                request_id=uuid4(),
                metadata={'worker': i},
            ).sequence

        with ThreadPoolExecutor(max_workers=8) as executor:
            sequences = list(executor.map(write, range(16)))

        self.assertEqual(sorted(sequences), list(range(1, 17)))
        self.assertEqual(AuditLog.objects.count(), 16)
        state = AuditChainState.objects.get(pk=1)
        self.assertEqual(state.last_sequence, 16)
        self.assertEqual(state.last_hash, AuditLog.objects.get(sequence=16).entry_hash)
        self.assertTrue(verify_audit_chain())
