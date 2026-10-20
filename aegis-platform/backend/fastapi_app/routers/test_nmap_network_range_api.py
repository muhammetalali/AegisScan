from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fastapi_app.routers import capabilities as router


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ('asset_type', 'target', 'expected_scan_type'),
    [
        ('network_range', '192.168.49.0/24', 'network'),
        ('ip_address', '192.168.49.128', 'ip'),
        ('domain', 'example.test', 'ip'),
    ],
)
async def test_existing_governed_nmap_api_uses_asset_appropriate_scan_type(
    monkeypatch, asset_type, target, expected_scan_type
):
    """No live scan, DB, policy replacement, or separate API is used here."""
    asset = SimpleNamespace(id='asset-1', name='authorized test asset', type=asset_type)
    captured = []

    async def allowed_asset(asset_id, project_id, user_id):
        assert (asset_id, project_id, user_id) == ('asset-1', 'project-1', 'owner-1')
        return asset

    async def create_scan(scan_request, user_id, *, execution_draft):
        captured.append((scan_request, execution_draft))
        assert user_id == 'owner-1'
        return SimpleNamespace(
            id='scan-1', config=scan_request.config,
            execution_contract={}, execution_contract_fingerprint='test-fingerprint',
            execution_correlation_id='test-correlation',
        ), ['nmap'], True

    async def attach_task(scan_id, task_id):
        assert (scan_id, task_id) == ('scan-1', 'celery-1')
        return SimpleNamespace(
            id='scan-1', config=captured[0][0].config,
            execution_contract={}, execution_contract_fingerprint='test-fingerprint',
            execution_correlation_id='test-correlation',
        )

    async def serialize(scan):
        return {'id': scan.id, 'scan_type': captured[0][0].scan_type}

    monkeypatch.setattr(router, '_asset_for_execution', allowed_asset)
    monkeypatch.setattr(router, 'asset_target', lambda value: target)
    monkeypatch.setattr(router, '_create_scan', create_scan)
    monkeypatch.setattr(router, '_attach_celery_task', attach_task)
    monkeypatch.setattr(router, '_serialize_scan', serialize)
    monkeypatch.setitem(router._TASKS, 'nmap', SimpleNamespace(delay=lambda scan_id: SimpleNamespace(id='celery-1')))

    result = await router.execute_capability(
        'network.nmap',
        router.CapabilityExecutionRequest(project_id='project-1', asset_id='asset-1'),
        user={'user_id': 'owner-1'},
    )
    scan_request, execution_draft = captured[0]
    assert scan_request.scan_type == expected_scan_type
    assert scan_request.config['target'] == target
    assert scan_request.engines == ['nmap']
    assert execution_draft.capability_id == 'network.nmap'
    assert result['scan']['scan_type'] == expected_scan_type


@pytest.mark.asyncio
async def test_nmap_rejects_unsupported_asset_before_creating_any_scan(monkeypatch):
    async def wrong_asset(*args):
        return SimpleNamespace(id='asset-1', name='test', type='website')

    async def no_scan(*args, **kwargs):
        pytest.fail('An unsupported target must not cause a scan')

    monkeypatch.setattr(router, '_asset_for_execution', wrong_asset)
    monkeypatch.setattr(router, '_create_scan', no_scan)
    with pytest.raises(HTTPException) as rejected:
        await router.execute_capability(
            'network.nmap',
            router.CapabilityExecutionRequest(project_id='project-1', asset_id='asset-1'),
            user={'user_id': 'owner-1'},
        )
    assert rejected.value.status_code == 409
