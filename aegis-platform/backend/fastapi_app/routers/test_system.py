from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fastapi_app.routers import system


def test_unsupported_admin_operation_is_explicit_501():
    for operation in ('Settings management', 'Backup management', 'Maintenance window management', 'Feature flag management'):
        with pytest.raises(HTTPException) as exc:
            system._unsupported(operation)
        assert exc.value.status_code == 501
        assert operation in str(exc.value.detail)


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


def test_system_monitor_rejects_anonymous_requests_on_both_existing_prefixes():
    app = FastAPI()
    app.include_router(system.router, prefix='/system')
    app.include_router(system.router, prefix='/api/v1/system')
    client = TestClient(app)
    for prefix in ('/system', '/api/v1/system'):
        assert client.get(f'{prefix}/metrics').status_code == 401
        assert client.get(f'{prefix}/services').status_code == 401
        assert client.get(f'{prefix}/settings').status_code == 401


def test_existing_monitor_permission_preserves_real_metrics_and_explicit_501(monkeypatch):
    app = FastAPI()
    app.include_router(system.router, prefix='/api/v1/system')
    # This is the API's existing system.monitor permission dependency, not
    # a new role or special-case auth path.
    permission_check = system.router.dependencies[0].dependency
    app.dependency_overrides[permission_check] = lambda: {'user_id': 'authorized-monitor'}
    monkeypatch.setattr(system, '_system_cpu_percent', lambda: 10.0)
    monkeypatch.setattr(system, '_system_memory_percent', lambda: 20.0)
    monkeypatch.setattr(system, '_disk_percent', lambda: 30.0)
    client = TestClient(app)
    metrics = client.get('/api/v1/system/metrics')
    assert metrics.status_code == 200
    assert {item['metric_type']: item['value'] for item in metrics.json()} == {
        'cpu_usage': 10.0, 'memory_usage': 20.0, 'disk_usage': 30.0,
    }
    unsupported = client.get('/api/v1/system/settings')
    assert unsupported.status_code == 501
    assert 'not implemented' in unsupported.json()['detail']
