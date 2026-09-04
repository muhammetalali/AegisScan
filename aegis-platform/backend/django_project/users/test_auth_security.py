import pytest
from django.test import Client

from django_project.users.models import User


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
