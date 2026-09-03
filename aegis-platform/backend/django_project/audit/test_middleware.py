import uuid

import pytest
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.test import RequestFactory

from django_project.audit.middleware import EnterpriseAuditMiddleware
from django_project.audit.models import AuditLog


@pytest.mark.django_db
def test_authenticated_state_changing_api_request_is_persisted():
    User = get_user_model()
    user = User.objects.create_user(
        email=f'audit-{uuid.uuid4().hex}@aegisscan.local',
        password='Strong-Audit-Pass!123',
        role='security_manager',
        is_active=True,
        is_verified=True,
    )
    request = RequestFactory().post('/api/v1/projects/', data={'name': 'audit-test'}, content_type='application/json')
    request.user = user

    middleware = EnterpriseAuditMiddleware(lambda _request: JsonResponse({'ok': True}, status=201))
    middleware.process_request(request)
    response = middleware.process_response(request, JsonResponse({'ok': True}, status=201))

    assert response.status_code == 201
    audit = AuditLog.objects.get(request_id=request._audit_request_id)
    assert audit.user_id == user.id
    assert audit.action == AuditLog.Action.API_REQUEST
    assert audit.result == AuditLog.Result.SUCCESS
    assert audit.resource_type == 'projects'
    assert audit.metadata['method'] == 'POST'
    assert audit.metadata['status_code'] == 201


@pytest.mark.django_db
def test_ignored_health_requests_do_not_create_audit_records():
    request = RequestFactory().post('/health', data={})
    request.user = type('User', (), {'is_authenticated': False})()
    middleware = EnterpriseAuditMiddleware(lambda _request: JsonResponse({'ok': True}, status=200))
    middleware.process_request(request)
    middleware.process_response(request, JsonResponse({'ok': True}, status=200))

    assert not AuditLog.objects.filter(request_id=request._audit_request_id).exists()
