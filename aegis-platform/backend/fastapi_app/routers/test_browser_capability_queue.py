from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.routers import capabilities as router


@pytest.mark.asyncio
@pytest.mark.parametrize('capability_id', ['browser.dom-snapshot', 'browser.spa-discovery'])
async def test_browser_native_capabilities_use_dedicated_browser_queue(monkeypatch, capability_id):
    """A browser tool must never execute on the read-only scanner worker."""
    asset = SimpleNamespace(id='asset-1', name='Authorized website', type='website')
    created = SimpleNamespace(
        id='scan-1', config={}, execution_contract={},
        execution_contract_fingerprint='test-fingerprint',
        execution_correlation_id='test-correlation',
    )
    dispatches = []

    async def get_asset(asset_id, project_id, user_id):
        assert (asset_id, project_id, user_id) == ('asset-1', 'project-1', 'owner-1')
        return asset

    async def make_scan(*args):
        assert args[0] == capability_id
        return created, True

    async def attach_task(scan_id, task_id):
        assert (scan_id, task_id) == ('scan-1', 'task-1')
        return created

    async def serialize(scan):
        return {'id': scan.id}

    def submit_to_queue(*, args, queue, routing_key):
        dispatches.append((args, queue, routing_key))
        return SimpleNamespace(id='task-1')

    def wrong_worker(*args):
        pytest.fail('Browser scan was dispatched to the scanner default queue')

    monkeypatch.setattr(router, '_asset_for_execution', get_asset)
    monkeypatch.setattr(router, 'asset_target', lambda _: 'https://example.test')
    monkeypatch.setattr(router, '_create_native_scan', make_scan)
    monkeypatch.setattr(router, '_attach_celery_task', attach_task)
    monkeypatch.setattr(router, '_serialize_scan', serialize)
    monkeypatch.setattr(router.run_native_capability_scan, 'apply_async', submit_to_queue)
    monkeypatch.setattr(router.run_native_capability_scan, 'delay', wrong_worker)

    result = await router.execute_capability(
        capability_id,
        router.CapabilityExecutionRequest(project_id='project-1', asset_id='asset-1', depth='quick'),
        user={'user_id': 'owner-1'},
    )

    assert result['scan']['id'] == 'scan-1'
    assert dispatches == [(['scan-1'], router.BROWSER_QUEUE, router.BROWSER_QUEUE)]
