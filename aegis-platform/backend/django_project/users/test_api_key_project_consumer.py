"""Opt-in API key consumer: real scoped project HTTP authentication."""
import hashlib
from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from django_project.projects.models import Project
from django_project.users.models import APIKey, User

pytestmark = pytest.mark.django_db


@pytest.fixture
def key_scope():
    user = User.objects.create_user(
        email='key-reader@example.invalid', password='LocalKeyPassword#123!',
        role='admin',
    )
    other = User.objects.create_user(
        email='unrelated-key@example.invalid', role='admin',
    )
    owned = Project.objects.create(
        owner=user, name='Owned tenant project', slug='owned-key-project',
    )
    Project.objects.create(
        owner=other, name='Other tenant project', slug='other-key-project',
    )
    material = 'aegis_' + 'k' * 43
    key = APIKey.objects.create(
        user=user, name='Project read key', key_prefix=material[:12],
        key_hash=hashlib.sha256(material.encode()).hexdigest(),
        permissions=['project.read'],
        expires_at=timezone.now() + timedelta(days=1),
    )
    client = APIClient()
    client.credentials(HTTP_X_API_KEY=material)
    return user, owned, key, material, client


def test_project_read_key_authenticates_and_limits_tenant_records(key_scope):
    user, project, key, material, client = key_scope
    response = client.get('/api/v1/projects/')
    assert response.status_code == 200, response.data
    rows = response.data.get('results', []) if isinstance(response.data, dict) else response.data
    ids = {str(row['id']) for row in rows}
    assert str(project.pk) in ids
    assert len(ids) == 1
    key.refresh_from_db()
    assert key.last_used_at is not None
    assert key.last_used_ip is not None


def test_key_permissions_block_mutation_even_for_admin(key_scope):
    _, _, _, _, client = key_scope
    response = client.post('/api/v1/projects/', {
        'name': 'Not authorized', 'description': 'cannot escalate',
    }, format='json')
    assert response.status_code == 403, response.data


def test_revoked_and_expired_key_fails_authentication(key_scope):
    _, _, key, _, client = key_scope
    key.expires_at = timezone.now() - timedelta(seconds=1)
    key.save(update_fields=['expires_at'])
    assert client.get('/api/v1/projects/').status_code == 401
    key.expires_at = timezone.now() + timedelta(hours=1)
    key.is_active = False
    key.save(update_fields=['expires_at', 'is_active'])
    assert client.get('/api/v1/projects/').status_code == 401


def test_user_deactivation_and_bad_key_fail_closed(key_scope):
    user, _, _, material, client = key_scope
    client.credentials(HTTP_X_API_KEY=material + 'invalid')
    assert client.get('/api/v1/projects/').status_code == 401
    client.credentials(HTTP_X_API_KEY=material)
    user.is_active = False
    user.save(update_fields=['is_active'])
    assert client.get('/api/v1/projects/').status_code == 401


def test_key_does_not_authenticate_unopted_management_endpoints(key_scope):
    _, _, _, _, client = key_scope
    assert client.get('/api/v1/auth/api-keys/').status_code == 401


def test_valid_jwt_or_cookie_login_is_not_replaced_by_key_auth(key_scope):
    user, project, _, _, _ = key_scope
    client = APIClient()
    client.force_authenticate(user=user)
    result = client.get('/api/v1/projects/')
    assert result.status_code == 200, result.data


def test_key_without_project_read_scope_never_reads_projects(key_scope):
    _, project, key, _, client = key_scope
    key.permissions = ['scan.read']
    key.save(update_fields=['permissions'])
    assert client.get('/api/v1/projects/').status_code == 403
    assert client.get(f'/api/v1/projects/{project.pk}/').status_code == 403


def test_key_does_not_override_read_only_policy_when_create_scope_exists(key_scope):
    _, _, key, _, client = key_scope
    key.permissions = ['project.read', 'project.create']
    key.save(update_fields=['permissions'])
    result = client.post('/api/v1/projects/', {'name': 'Denied project'}, format='json')
    assert result.status_code == 403


def test_rotated_key_material_rejects_original_immediately(key_scope):
    _, _, key, old_material, client = key_scope
    import secrets

    replacement_material = 'aegis_' + secrets.token_urlsafe(32)
    APIKey.objects.create(
        user=key.user, name='Replacement', permissions=key.permissions,
        key_hash=hashlib.sha256(replacement_material.encode()).hexdigest(),
        key_prefix=replacement_material[:12],
    )
    key.is_active = False
    key.save(update_fields=['is_active'])
    assert client.get('/api/v1/projects/').status_code == 401
    client.credentials(HTTP_X_API_KEY=replacement_material)
    assert client.get('/api/v1/projects/').status_code == 200


def test_mfa_flag_cannot_be_bypassed_using_older_api_key(key_scope):
    user, _, _, _, client = key_scope
    user.two_factor_enabled = True
    user.save(update_fields=['two_factor_enabled'])
    assert client.get('/api/v1/projects/').status_code == 401
