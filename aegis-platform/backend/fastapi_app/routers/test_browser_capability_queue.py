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


@pytest.mark.parametrize('capability_id', ['browser.dom-snapshot', 'browser.spa-discovery'])
@pytest.mark.parametrize('delivery_queue', ['browser', 'scanners'])
def test_native_browser_worker_rejects_wrong_queue_and_accepts_browser_queue(
    monkeypatch, capability_id, delivery_queue
):
    """Router and worker must agree; scanner queue must reject browser work."""
    from fastapi_app.tasks import native_capabilities as worker

    scan = SimpleNamespace(id='scan-1', config={'capability_id': capability_id})
    queryset = SimpleNamespace(get=lambda **_kwargs: scan)
    monkeypatch.setattr(
        worker, 'Scan',
        SimpleNamespace(objects=SimpleNamespace(select_related=lambda *args: queryset)),
    )
    monkeypatch.setattr(
        worker, 'get_capability',
        lambda _: SimpleNamespace(id=capability_id, tool='aegis-browser-security'),
    )
    monkeypatch.setattr(worker, 'is_wstg_internal_capability', lambda _: False)
    monkeypatch.setattr(worker, 'get_native_tool_spec', lambda _: SimpleNamespace(timeout=60))
    monkeypatch.setattr(worker, '_engine', lambda *args: SimpleNamespace())
    monkeypatch.setattr(worker, '_execution', lambda *args: SimpleNamespace())
    monkeypatch.setattr(worker, '_fail', lambda *args: {'rejected': True, 'reason': args[2]})
    monkeypatch.setattr(
        worker, 'terminal_scan_delivery',
        lambda *args: {'redelivered': True, 'scan_id': 'scan-1'},
    )
    task = worker.run_native_capability_scan
    task.push_request(
        called_directly=False, delivery_info={'routing_key': delivery_queue},
    )
    try:
        result = task.run('scan-1')
    finally:
        task.pop_request()

    if delivery_queue == 'browser':
        assert result == {'redelivered': True, 'scan_id': 'scan-1'}
    else:
        assert result.get('rejected') is True
        assert "requires queue 'browser'" in result['reason']
