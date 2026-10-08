"""Exact API key lifecycle and RBAC acceptance for the governed user API."""
import hashlib

import pytest
from rest_framework.test import APIClient

from django_project.audit.models import AuditLog
from django_project.audit.services import verify_audit_chain
from django_project.users.models import APIKey, User


@pytest.mark.django_db(transaction=True)
def test_api_key_create_rotate_revoke_is_atomic_and_secret_safe():
    admin = User.objects.create_user(email='key-admin@example.invalid', password='StrongPass#12345', role='admin')
    client = APIClient()
    client.force_authenticate(user=admin)
    response = client.post('/api/v1/auth/api-keys/', {'name':'reality-key','permissions':['project.read']}, format='json')
    assert response.status_code == 201, response.data
    original = response.data
    assert original['key'].startswith('aegis_')
    assert hashlib.sha256(original['key'].encode()).hexdigest() == APIKey.objects.get(pk=original['id']).key_hash
    listed = client.get('/api/v1/auth/api-keys/')
    assert listed.status_code == 200
    assert original['key'] not in str(listed.data)
    assert (listed.data['results'] if isinstance(listed.data,dict) else listed.data)[0].get('key') is None

    rotated = client.post(f"/api/v1/auth/api-keys/{original['id']}/rotate/", {}, format='json')
    assert rotated.status_code == 201, rotated.data
    replacement = rotated.data
    assert replacement['key'] != original['key']
    assert replacement['permissions'] == ['project.read']
    assert APIKey.objects.get(pk=original['id']).is_active is False
    assert APIKey.objects.get(pk=replacement['id']).is_active is True

    blocked = client.post(f"/api/v1/auth/api-keys/{original['id']}/rotate/", {}, format='json')
    assert blocked.status_code == 409
    revocation = client.delete(f"/api/v1/auth/api-keys/{replacement['id']}/")
    assert revocation.status_code == 204
    assert not APIKey.objects.get(pk=replacement['id']).is_active
    assert replacement['key'] not in str(client.get('/api/v1/auth/api-keys/').data)
    assert AuditLog.objects.filter(action=AuditLog.Action.API_KEY_CREATE).count() == 2
    assert AuditLog.objects.filter(action=AuditLog.Action.API_KEY_REVOKE).count() == 2
    assert original['key'] not in str(AuditLog.objects.values_list('metadata', flat=True))
    assert replacement['key'] not in str(AuditLog.objects.values_list('metadata', flat=True))
    assert verify_audit_chain()[0] is True


@pytest.mark.django_db
def test_api_key_viewer_denied_and_no_cross_user_key_access():
    admin = User.objects.create_user(email='key-operator@example.invalid', role='admin')
    other = User.objects.create_user(email='key-other@example.invalid', role='admin')
    viewer = User.objects.create_user(email='key-viewer@example.invalid', role='viewer')
    owner_client = APIClient()
    owner_client.force_authenticate(user=admin)
    response=owner_client.post('/api/v1/auth/api-keys/', {'name':'owner-key','permissions':['project.read']}, format='json')
    assert response.status_code == 201, response.data
    key_id = response.data['id']
    viewer_client = APIClient()
    viewer_client.force_authenticate(user=viewer)
    assert viewer_client.get('/api/v1/auth/api-keys/').status_code == 403
    assert viewer_client.post('/api/v1/auth/api-keys/', {'name':'x','permissions':['project.read']}, format='json').status_code == 403
    assert viewer_client.post(f'/api/v1/auth/api-keys/{key_id}/rotate/', {}, format='json').status_code == 403
    cross_client = APIClient()
    cross_client.force_authenticate(user=other)
    assert cross_client.get(f'/api/v1/auth/api-keys/{key_id}/').status_code == 404
    assert cross_client.delete(f'/api/v1/auth/api-keys/{key_id}/').status_code == 404
    assert cross_client.post(f'/api/v1/auth/api-keys/{key_id}/rotate/', {}, format='json').status_code == 404


@pytest.mark.django_db
def test_key_permissions_never_escalate_creator_role():
    manager = User.objects.create_user(email='key-manager@example.invalid',role='security_manager')
    client = APIClient()
    client.force_authenticate(user=manager)
    response = client.post('/api/v1/auth/api-keys/', {'name':'overreach','permissions':['user.manage_roles']},format='json')
    assert response.status_code == 400
    assert APIKey.objects.count() == 0
    allowed = client.post('/api/v1/auth/api-keys/', {'name':'valid','permissions':['project.read','scan.read']},format='json')
    assert allowed.status_code == 201, allowed.data
    assert allowed.data['permissions']==['project.read','scan.read']
