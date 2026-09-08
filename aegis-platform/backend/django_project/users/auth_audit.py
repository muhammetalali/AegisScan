from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from django_project.audit.models import AuditLog, SecurityEvent
from django_project.audit.services import append_audit, client_ip_from_request

from .models import LoginAttempt, User


_LOCAL_DETECTION_LOCK = threading.Lock()


def _advisory_key(value: str) -> int:
    return int.from_bytes(hashlib.sha256(value.encode('utf-8')).digest()[:8], 'big', signed=True)


@contextmanager
def _serialize_detection(key: str):
    if connection.vendor == 'postgresql':
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [_advisory_key(key)])
        yield
        return
    with _LOCAL_DETECTION_LOCK:
        yield


def _create_detection_if_needed(*, key: str, query: Q, event_query: Q, attempt, target_user, source_ip) -> None:
    threshold = settings.AUTH_BRUTE_FORCE_THRESHOLD
    window_seconds = settings.AUTH_BRUTE_FORCE_WINDOW_SECONDS
    window_start = timezone.now() - timedelta(seconds=window_seconds)
    with _serialize_detection(key):
        failures = LoginAttempt.objects.filter(success=False, created_at__gte=window_start).filter(query).count()
        if failures < threshold:
            return
        active = SecurityEvent.objects.select_for_update().filter(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            status__in=[SecurityEvent.Status.NEW, SecurityEvent.Status.INVESTIGATING],
            created_at__gte=window_start,
        ).filter(event_query).exists()
        if active:
            return
        SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            severity=SecurityEvent.Severity.HIGH,
            title='Repeated authentication failures detected',
            description=f'{failures} rejected login attempts exceeded the configured threshold.',
            source_ip=source_ip,
            target_user=target_user,
            indicators=[key, f'auth_failures:{failures}'],
            raw_data={
                'detection_key': key,
                'threshold': threshold,
                'window_seconds': window_seconds,
                'observed_failures': failures,
                'last_attempt_id': str(attempt.id),
            },
        )


def _detect_brute_force(*, attempt, attempted_email: str, target_user) -> None:
    source_ip = str(attempt.ip_address)
    _create_detection_if_needed(
        key=f'ip:{source_ip}',
        query=Q(ip_address=source_ip),
        event_query=Q(source_ip=source_ip, target_user__isnull=True),
        attempt=attempt,
        target_user=None,
        source_ip=source_ip,
    )
    if target_user is not None:
        _create_detection_if_needed(
            key=f'identity:{target_user.pk}',
            query=Q(email=attempted_email),
            event_query=Q(source_ip__isnull=True, target_user=target_user),
            attempt=attempt,
            target_user=target_user,
            source_ip=None,
        )


@transaction.atomic
def record_login_event(request, *, email: str, success: bool, user=None, failure_reason: str = '') -> None:
    attempted_email = (email or '').strip().lower()[:254]
    ip_address = client_ip_from_request(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')[:10000]
    target_user = user or User.objects.filter(email__iexact=attempted_email).first()
    attempt = LoginAttempt.objects.create(
        email=attempted_email,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        failure_reason=failure_reason[:100],
    )
    metadata = {'attempted_email': attempted_email, 'authentication_method': 'password'}
    if target_user is not None:
        metadata['target_user_id_snapshot'] = str(target_user.pk)
    append_audit(
        user=user,
        action=AuditLog.Action.LOGIN if success else AuditLog.Action.LOGIN_FAILED,
        result=AuditLog.Result.SUCCESS if success else AuditLog.Result.FAILURE,
        resource_type='authentication',
        resource_id=str(getattr(target_user, 'pk', '') or ''),
        resource_repr='Interactive user login',
        metadata=metadata,
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=getattr(getattr(request, 'session', None), 'session_key', None) or '',
        request_id=(getattr(request, '_audit_request_id', None) or AuditLog._meta.get_field('request_id').default()),
        error_message='' if success else 'Authentication rejected',
    )
    if not success:
        _detect_brute_force(attempt=attempt, attempted_email=attempted_email, target_user=target_user)
    request._auth_audit_recorded = True
