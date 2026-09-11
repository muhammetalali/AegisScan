import asyncio
import time

import pytest

from fastapi_app import main


@pytest.fixture(autouse=True)
def reset_readiness_state():
    original=dict(main._readiness_state)
    main._readiness_state.update({'ready':False,'dependencies':None,'checked_at':0.0})
    yield
    main._readiness_state.clear()
    main._readiness_state.update(original)


@pytest.mark.asyncio
async def test_readiness_refresh_records_success_without_request_path_probe(monkeypatch):
    calls=[]
    def probe():
        calls.append('probe')
        return {'database':'ok','redis':'ok'}
    monkeypatch.setattr(main,'_check_dependencies_sync',probe)

    await main._refresh_dependency_readiness()
    snapshot=main._readiness_snapshot()

    assert calls==['probe']
    assert snapshot['ready'] is True
    assert snapshot['dependencies']=={'database':'ok','redis':'ok'}


@pytest.mark.asyncio
async def test_readiness_refresh_fails_closed_after_probe_failure(monkeypatch):
    main._readiness_state.update({
        'ready':True,
        'dependencies':{'database':'ok','redis':'ok'},
        'checked_at':time.monotonic(),
    })
    def probe():
        raise RuntimeError('database unavailable')
    monkeypatch.setattr(main,'_check_dependencies_sync',probe)

    await main._refresh_dependency_readiness()
    snapshot=main._readiness_snapshot()

    assert snapshot['ready'] is False
    assert snapshot['dependencies'] is None


def test_readiness_snapshot_fails_closed_when_monitor_is_stale():
    main._readiness_state.update({
        'ready':True,
        'dependencies':{'database':'ok','redis':'ok'},
        'checked_at':time.monotonic()-main._READINESS_STALE_AFTER_SECONDS-0.1,
    })

    snapshot=main._readiness_snapshot()

    assert snapshot['ready'] is False
    assert snapshot['dependencies'] is None
