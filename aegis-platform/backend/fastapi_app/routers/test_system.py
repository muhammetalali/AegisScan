from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

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
