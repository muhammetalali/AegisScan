from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from audit.models import AuditLog
from .models import User, UserRole


class UserAuditIntegrationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='audit-user@example.test',
            password='AegisUserTest-2026!',
            first_name='Audit',
            last_name='User',
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
        )
        self.login_url = reverse('token_obtain_pair')
        self.audit_actions = lambda: list(AuditLog.objects.values_list('action', flat=True))

    def test_successful_login_creates_audit_event(self):
        response = self.client.post(
            self.login_url,
            {'email': self.user.email, 'password': 'AegisUserTest-2026!'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        event = AuditLog.objects.get(action='auth.login', result=AuditLog.Result.SUCCESS)
        self.assertEqual(event.user_id, self.user.id)
        self.assertEqual(event.resource_type, 'User')
        self.assertNotIn('password', event.metadata)

    def test_failed_login_creates_audit_event_without_credentials(self):
        response = self.client.post(
            self.login_url,
            {'email': self.user.email, 'password': 'wrong-password'},
            format='json',
        )
        self.assertEqual(response.status_code, 401)
        event = AuditLog.objects.filter(action='auth.login', result=AuditLog.Result.FAILURE).latest('created_at')
        self.assertEqual(event.user_id, self.user.id)
        self.assertEqual(event.metadata.get('reason'), 'invalid_credentials')
        self.assertNotIn('wrong-password', event.metadata.values())

    def test_password_change_creates_audit_event(self):
        self.client.force_authenticate(self.user)
        response = self.client.post(
            '/api/v1/users/change_password/',
            {
                'old_password': 'AegisUserTest-2026!',
                'new_password': 'AegisUserTest-2026-New!',
                'new_password_confirm': 'AegisUserTest-2026-New!',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        event = AuditLog.objects.get(action='auth.password.change', result=AuditLog.Result.SUCCESS)
        self.assertEqual(event.user_id, self.user.id)
        self.assertNotIn('new_password', event.metadata)
        self.assertNotIn('old_password', event.metadata)

    def test_logout_creates_audit_event(self):
        self.client.force_authenticate(self.user)
        response = self.client.post('/api/v1/users/logout/', {}, format='json')
        self.assertEqual(response.status_code, 200)
        event = AuditLog.objects.get(action='auth.logout', result=AuditLog.Result.SUCCESS)
        self.assertEqual(event.user_id, self.user.id)

    def test_register_creates_audit_event(self):
        response = self.client.post(
            '/api/v1/auth/register/',
            {
                'email': 'new-audit-user@example.test',
                'first_name': 'New',
                'last_name': 'Audit',
                'password': 'NewAuditUser-2026!',
                'password_confirm': 'NewAuditUser-2026!',
                'role': UserRole.VIEWER,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 201)
        user = User.objects.get(email='new-audit-user@example.test')
        event = AuditLog.objects.get(action='auth.register', result=AuditLog.Result.SUCCESS, user=user)
        self.assertEqual(event.resource_id, str(user.pk))

    def test_audit_hash_chain_is_valid_after_user_events(self):
        self.client.post(
            self.login_url,
            {'email': self.user.email, 'password': 'wrong-password'},
            format='json',
        )
        self.client.post(
            self.login_url,
            {'email': self.user.email, 'password': 'AegisUserTest-2026!'},
            format='json',
        )
        self.assertTrue(AuditLog.objects.filter(user=self.user).exists())
