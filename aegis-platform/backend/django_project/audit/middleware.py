from __future__ import annotations

import ipaddress
import time
import uuid

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

from django_project.audit.models import AuditLog


class EnterpriseAuditMiddleware(MiddlewareMixin):
    """Persist an auditable record for authenticated state-changing API calls."""

    AUDITED_METHODS = frozenset({'POST', 'PUT', 'PATCH', 'DELETE'})
    IGNORED_PREFIXES = (
        '/admin/',
        '/static/',
        '/media/',
    )
    IGNORED_PATHS = frozenset({'/health', '/health/', '/ready'})

    def process_request(self, request):
        request._audit_started_at = time.monotonic()
        request._audit_request_id = uuid.uuid4()

    def process_response(self, request, response):
        self._record(request, response, None)
        return response

    def process_exception(self, request, exception):
        self._record(request, None, exception)
        return None

    def _record(self, request, response, exception) -> None:
        path = request.path
        if request.method not in self.AUDITED_METHODS or not path.startswith('/api/'):
            return
        if path in self.IGNORED_PATHS or any(path.startswith(prefix) for prefix in self.IGNORED_PREFIXES):
            return
        if getattr(request, '_audit_recorded', False):
            return
        request._audit_recorded = True

        started_at = getattr(request, '_audit_started_at', time.monotonic())
        status_code = getattr(response, 'status_code', 500)
        result = AuditLog.Result.SUCCESS if status_code < 400 and exception is None else AuditLog.Result.FAILURE
        resource_type, resource_id = self._resource(path)
        user = getattr(request, 'user', None)
        if not getattr(user, 'is_authenticated', False):
            user = None
        # A request can have SessionMiddleware attached before a session has
        # ever been materialized. In that state session_key is None, but the
        # durable audit schema intentionally uses an empty string for "no
        # established session" rather than a nullable identifier.
        session = getattr(request, 'session', None)
        session_id = getattr(session, 'session_key', None) or ''

        try:
            AuditLog.objects.create(
                user=user,
                action=AuditLog.Action.API_REQUEST,
                result=result,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_repr=f'{request.method} {path}'[:200],
                metadata={
                    'method': request.method,
                    'path': path,
                    'status_code': status_code,
                    'query_keys': sorted(request.GET.keys()),
                },
                ip_address=self._client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:10000],
                session_id=session_id,
                request_id=getattr(request, '_audit_request_id', uuid.uuid4()),
                error_message=str(exception)[:4000] if exception else '',
                duration_ms=max(0, round((time.monotonic() - started_at) * 1000)),
            )
        except Exception:
            if settings.DEBUG:
                raise

    @staticmethod
    def _resource(path: str) -> tuple[str, str]:
        parts = [part for part in path.strip('/').split('/') if part]
        if len(parts) < 3 or parts[0] != 'api' or parts[1] != 'v1':
            return ('api', '')
        resource_type = parts[2][:50]
        resource_id = parts[3][:100] if len(parts) > 3 else ''
        return resource_type, resource_id

    @staticmethod
    def _client_ip(request) -> str:
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        candidates = [value.strip() for value in forwarded.split(',') if value.strip()]
        candidates.append(request.META.get('HTTP_X_REAL_IP', '').strip())
        candidates.append(request.META.get('REMOTE_ADDR', '').strip())
        for candidate in candidates:
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
        return '127.0.0.1'
