import pytest
from django.test import Client

from django_project.users.models import User
from django_project.users.models import LoginAttempt
from django_project.audit.models import AuditLog
from django_project.audit.services import verify_audit_chain


@pytest.mark.django_db
def test_csrf_endpoint_sets_token_cookie():
    client = Client(enforce_csrf_checks=True)
    response = client.get('/api/v1/auth/csrf/')

    assert response.status_code == 200
    assert response.json()['csrfToken']
    assert 'csrftoken' in response.cookies


@pytest.mark.django_db
def test_login_rejects_missing_csrf_token():
    User.objects.create_user(
        email='csrf-test@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='CSRF',
        last_name='Test',
    )
    client = Client(enforce_csrf_checks=True)

    response = client.post(
        '/api/v1/auth/login/',
        {'email': 'csrf-test@example.invalid', 'password': 'Strong-Test-Password-123!'},
    )

    assert response.status_code == 403
    assert 'aegis_access' not in response.cookies
    assert 'aegis_refresh' not in response.cookies


@pytest.mark.django_db
def test_login_accepts_csrf_token_and_sets_httponly_jwt_cookies(settings):
    User.objects.create_user(
        email='csrf-success@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='CSRF',
        last_name='Success',
    )
    client = Client(enforce_csrf_checks=True)
    csrf_response = client.get('/api/v1/auth/csrf/')
    csrf_token = csrf_response.json()['csrfToken']

    response = client.post(
        '/api/v1/auth/login/',
        {'email': 'csrf-success@example.invalid', 'password': 'Strong-Test-Password-123!'},
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 200
    assert response.json()['authenticated'] is True
    assert response.cookies['aegis_access']['httponly'] is True
    assert response.cookies['aegis_refresh']['httponly'] is True
    assert response.cookies['aegis_access']['samesite'].lower() == 'lax'
    assert response.cookies['aegis_refresh']['samesite'].lower() == 'lax'
    assert bool(response.cookies['aegis_access']['secure']) == settings.AUTH_COOKIE_SECURE
    assert bool(response.cookies['aegis_refresh']['secure']) == settings.AUTH_COOKIE_SECURE
    attempt = LoginAttempt.objects.get(email='csrf-success@example.invalid')
    assert attempt.success is True
    audit = AuditLog.objects.get(action=AuditLog.Action.LOGIN)
    assert audit.user_id is not None
    assert audit.metadata['attempted_email'] == 'csrf-success@example.invalid'
    assert audit.metadata['actor_id_snapshot'] == str(audit.user_id)
    assert len(audit.entry_hash) == 64
    assert verify_audit_chain()[0] is True


@pytest.mark.django_db
def test_failed_login_persists_semantic_attempt_and_hash_linked_audit():
    User.objects.create_user(
        email='failed-login@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Failed',
        last_name='Login',
    )
    client = Client(enforce_csrf_checks=True)
    csrf_token = client.get('/api/v1/auth/csrf/').json()['csrfToken']

    response = client.post(
        '/api/v1/auth/login/',
        {'email': 'failed-login@example.invalid', 'password': 'Wrong-Password-123!'},
        HTTP_X_CSRFTOKEN=csrf_token,
        HTTP_X_FORWARDED_FOR='203.0.113.9, invalid-hop',
    )

    assert response.status_code == 401
    attempt = LoginAttempt.objects.get(email='failed-login@example.invalid')
    assert attempt.success is False
    assert str(attempt.ip_address) == '203.0.113.9'
    audit = AuditLog.objects.get(action=AuditLog.Action.LOGIN_FAILED)
    assert audit.result == AuditLog.Result.FAILURE
    assert audit.user_id is None
    assert audit.ip_address == '203.0.113.9'
    assert 'Wrong-Password' not in str(audit.metadata)
    assert 'Wrong-Password' not in audit.error_message
    assert verify_audit_chain()[0] is True


@pytest.mark.django_db
def test_login_accepts_configured_reverse_proxy_origin(settings):
    settings.CSRF_TRUSTED_ORIGINS = ['http://nginx']
    User.objects.create_user(
        email='csrf-proxy@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='CSRF',
        last_name='Proxy',
    )
    client = Client(enforce_csrf_checks=True)
    csrf_response = client.get('/api/v1/auth/csrf/', HTTP_HOST='nginx')
    csrf_token = csrf_response.json()['csrfToken']

    response = client.post(
        '/api/v1/auth/login/',
        {'email': 'csrf-proxy@example.invalid', 'password': 'Strong-Test-Password-123!'},
        HTTP_HOST='nginx',
        HTTP_ORIGIN='http://nginx',
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 200
    assert response.json()['authenticated'] is True


@pytest.mark.django_db
def test_refresh_rejects_missing_csrf_token():
    client = Client(enforce_csrf_checks=True)
    csrf_response = client.get('/api/v1/auth/csrf/')
    csrf_token = csrf_response.json()['csrfToken']

    # A refresh cookie without the matching CSRF header must not be accepted.
    client.cookies['aegis_refresh'] = 'not-a-real-refresh-token'
    response = client.post('/api/v1/auth/refresh/')

    assert response.status_code == 403
    assert csrf_token
