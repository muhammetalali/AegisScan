from __future__ import annotations

import uuid

from django.test import TestCase
from starlette.requests import Request

from django_project.audit.models import AuditLog
from django_project.users.models import User
from fastapi_app.services.audit_writer import add_audit_entry


class AuditWriterTests(TestCase):
    def test_persists_actor_resource_and_request_context(self):
        user = User.objects.create_user(
            email='audit-writer@example.local',
            password='AuditWriter!2026',
            first_name='Audit',
            last_name='Writer',
        )
        request_id = uuid.uuid4()
        request = Request(
            {
                'type': 'http',
                'method': 'POST',
                'path': '/api/v1/vulnerabilities/test/remediation/close',
                'client': ('10.20.30.40', 51234),
                'headers': [
                    (b'user-agent', b'pytest-audit'),
                    (b'x-request-id', str(request_id).encode()),
                    (b'x-session-id', b'e2e-session-1'),
                ],
            }
        )

        entry = add_audit_entry(
            user=user.id,
            action=AuditLog.Action.VULN_FIX_VERIFY,
            target='finding-123',
            project='project-456',
            resource_type='vulnerability',
            resource_repr='finding-123',
            metadata={'workflow': 'remediation', 'operation': 'verify'},
            request=request,
        )

        self.assertEqual(entry.user_id, user.id)
        self.assertEqual(entry.action, AuditLog.Action.VULN_FIX_VERIFY)
        self.assertEqual(entry.resource_type, 'vulnerability')
        self.assertEqual(entry.resource_id, 'finding-123')
        self.assertEqual(entry.ip_address, '10.20.30.40')
        self.assertEqual(entry.user_agent, 'pytest-audit')
        self.assertEqual(entry.session_id, 'e2e-session-1')
        self.assertEqual(entry.request_id, request_id)
        self.assertEqual(entry.metadata['workflow'], 'remediation')
        self.assertEqual(entry.metadata['project_id'], 'project-456')

    def test_uses_generated_request_id_without_http_request(self):
        user = User.objects.create_user(
            email='audit-writer-system@example.local',
            password='AuditWriter!2026',
            first_name='System',
            last_name='Writer',
        )

        entry = add_audit_entry(
            user=user.id,
            action='decision_action.create',
            target='action-123',
            resource_type='decision_action',
        )

        self.assertEqual(entry.user_id, user.id)
        self.assertEqual(entry.resource_id, 'action-123')
        self.assertEqual(entry.resource_type, 'decision_action')
        self.assertEqual(entry.ip_address, '0.0.0.0')
        self.assertIsNotNone(entry.request_id)
