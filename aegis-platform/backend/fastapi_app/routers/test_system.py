from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from fastapi_app.routers import system


def test_unsupported_mutation_routes_are_not_advertised():
    # No fake button may suggest a backup/restore/flag write happened.
    advertised = {(route.path, method) for route in system.router.routes
                  for method in getattr(route, 'methods', [])}
    for path in ('/settings', '/backups', '/maintenance-windows', '/feature-flags'):
        assert (path, 'GET') in advertised
    assert ('/settings/{key}', 'GET') in advertised
    assert ('/settings/{key}', 'PATCH') not in advertised
    assert ('/backups', 'POST') not in advertised
    assert ('/backups/{backup_id}/restore', 'POST') not in advertised
    assert ('/maintenance-windows', 'POST') not in advertised
    assert ('/feature-flags', 'POST') not in advertised


def test_sensitive_system_settings_are_never_returned():
    from types import SimpleNamespace
    base = {
        'id': '123', 'key': 'access_token', 'name': 'Access token',
        'description': '', 'category': 'security',
        'value': {'token': 'must-not-leak'}, 'value_type': 'json',
        'requires_restart': False,
    }
    sensitive = system._setting_response(SimpleNamespace(**base, is_sensitive=True))
    assert sensitive.value == {}
    public = system._setting_response(SimpleNamespace(**{**base, 'key': 'worker_limit', 'value': 4}, is_sensitive=False))
    assert public.value == {'value': 4}


@pytest.mark.asyncio
async def test_system_management_reads_reuse_existing_orm_readers(monkeypatch):
    async def records(*args):
        return [{'id': 'reused-db-record'}]
    async def absent(*args):
        return None
    monkeypatch.setattr(system, '_read_settings', records)
    monkeypatch.setattr(system, '_read_backups', records)
    monkeypatch.setattr(system, '_read_maintenance_windows', records)
    monkeypatch.setattr(system, '_read_feature_flags', records)
    monkeypatch.setattr(system, '_read_setting', absent)
    assert await system.list_settings() == [{'id': 'reused-db-record'}]
    assert await system.list_backups() == [{'id': 'reused-db-record'}]
    assert await system.list_maintenance_windows() == [{'id': 'reused-db-record'}]
    assert await system.list_feature_flags() == [{'id': 'reused-db-record'}]
    with pytest.raises(HTTPException) as exc:
        await system.get_setting('missing')
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_metrics_are_measured_without_static_fallbacks(monkeypatch):
    monkeypatch.setattr(system, '_system_cpu_percent', lambda: 11.25)
    monkeypatch.setattr(system, '_system_memory_percent', lambda: 22.5)
    monkeypatch.setattr(system, '_disk_percent', lambda: 33.75)
    metrics = await system.get_metrics()
    assert {item.metric_type: item.value for item in metrics} == {
        'cpu_usage': 11.25,
        'memory_usage': 22.5,
        'disk_usage': 33.75,
    }
    assert all(item.timestamp for item in metrics)


@pytest.mark.parametrize('route', [
    '/system/metrics',
    '/system/services',
    '/api/v1/system/metrics',
    '/api/v1/system/services',
])
def test_system_telemetry_rejects_anonymous_access_before_collecting(route, monkeypatch):
    from fastapi.testclient import TestClient
    from fastapi_app.main import app

    def unexpected_probe(*_args, **_kwargs):
        pytest.fail('unauthenticated telemetry must never invoke a service probe')

    for function in (
        '_system_cpu_percent', '_system_memory_percent', '_disk_percent',
        '_postgres_probe', '_redis_probe', '_celery_probe', '_http_probe',
    ):
        monkeypatch.setattr(system, function, unexpected_probe)
    with TestClient(app) as client:
        result = client.get(route)
    assert result.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_system_telemetry_uses_existing_owner_and_delegated_permission_grants(settings, monkeypatch):
    from django.db import close_old_connections
    from fastapi.testclient import TestClient
    from django_project.users.models import User, UserRole
    from fastapi_app.core.dependencies import get_current_user
    from fastapi_app.main import app

    owner = User.objects.create_superuser(
        email='telemetry-owner@example.invalid', password='Strong-Test-Password-123!',
    )
    settings.AEGIS_PRIMARY_OWNER_EMAIL = owner.email
    viewer = User.objects.create_user(
        email='telemetry-viewer@example.invalid', password='Strong-Test-Password-123!',
        role=UserRole.VIEWER,
    )
    delegate = User.objects.create_user(
        email='telemetry-delegate@example.invalid', password='Strong-Test-Password-123!',
        role=UserRole.ADMIN, granted_permissions=['system.monitor'],
    )
    restricted_manager = User.objects.create_user(
        email='telemetry-manager@example.invalid', password='Strong-Test-Password-123!',
        role=UserRole.SECURITY_MANAGER, granted_permissions=['system.monitor'],
    )
    # The tests must neither connect to real services nor disclose their topology.
    for name, result in (
        ('_postgres_probe', ('healthy', 'fixture', 0, 0.0, None)),
        ('_redis_probe', ('healthy', 'fixture', 0, 0.0, None)),
        ('_celery_probe', ('healthy', 'fixture', 0, 0.0, None)),
    ):
        monkeypatch.setattr(system, name, lambda result=result: result)
    monkeypatch.setattr(system, '_http_probe', lambda *_: ('healthy', 'fixture', 0, 0.0, None))
    monkeypatch.setattr(system, '_system_cpu_percent', lambda: 10.0)
    monkeypatch.setattr(system, '_system_memory_percent', lambda: 20.0)
    monkeypatch.setattr(system, '_disk_percent', lambda: 30.0)

    try:
        with TestClient(app) as client:
            for actor, expected in ((viewer, 403), (restricted_manager, 403), (delegate, 200), (owner, 200)):
                app.dependency_overrides[get_current_user] = (
                    lambda actor_id=str(actor.id): {'user_id': actor_id}
                )
                for route in ('/api/v1/system/metrics', '/api/v1/system/services'):
                    response = client.get(route)
                    assert response.status_code == expected, (actor.role, route, response.text)
                    if expected == 200:
                        assert isinstance(response.json(), list)
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        close_old_connections()
