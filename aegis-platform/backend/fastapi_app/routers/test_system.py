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
