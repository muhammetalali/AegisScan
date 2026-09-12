import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import close_old_connections, connection
from django.test import RequestFactory

from django_project.audit.models import SecurityEvent
from django_project.audit.services import verify_audit_chain

from .auth_audit import record_login_event
from .models import LoginAttempt, User


def _request(ip_address: str):
    request = RequestFactory().post('/api/v1/auth/login/')
    request.META['REMOTE_ADDR'] = ip_address
    request.META['HTTP_USER_AGENT'] = 'AegisScan detection test'
    request._audit_request_id = uuid.uuid4()
    return request


@pytest.mark.django_db(transaction=True)
def test_repeated_failures_create_deduplicated_ip_and_identity_detections(settings):
    settings.AUTH_BRUTE_FORCE_THRESHOLD = 3
    settings.AUTH_BRUTE_FORCE_WINDOW_SECONDS = 600
    user = User.objects.create_user(email='target@example.invalid', password='Strong-Test-Pass-123!')

    for _ in range(4):
        record_login_event(
            _request('203.0.113.40'),
            email=user.email,
            success=False,
            failure_reason='authentication_failed',
        )

    assert LoginAttempt.objects.filter(email=user.email, success=False).count() == 4
    events = list(SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.BRUTE_FORCE))
    assert len(events) == 2
    assert {event.raw_data['detection_key'] for event in events} == {
        'ip:203.0.113.40',
        f'identity:{user.pk}',
    }
    assert all(event.raw_data['threshold'] == 3 for event in events)
    assert all(event.severity == SecurityEvent.Severity.HIGH for event in events)
    assert verify_audit_chain()[0] is True


@pytest.mark.django_db(transaction=True)
def test_postgresql_concurrent_failures_do_not_duplicate_active_detections(settings):
    if connection.vendor != 'postgresql':
        pytest.skip('PostgreSQL advisory-lock proof')
    settings.AUTH_BRUTE_FORCE_THRESHOLD = 3
    settings.AUTH_BRUTE_FORCE_WINDOW_SECONDS = 600
    user = User.objects.create_user(email='concurrent-target@example.invalid', password='Strong-Test-Pass-123!')

    def rejected_login(number: int) -> None:
        close_old_connections()
        try:
            record_login_event(
                _request('203.0.113.41'),
                email=user.email,
                success=False,
                failure_reason=f'concurrent_{number}',
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(rejected_login, range(8)))

    events = SecurityEvent.objects.filter(event_type=SecurityEvent.EventType.BRUTE_FORCE)
    assert events.count() == 2
    assert events.filter(source_ip='203.0.113.41', target_user__isnull=True).count() == 1
    assert events.filter(source_ip__isnull=True, target_user=user).count() == 1
    assert verify_audit_chain()[0] is True
