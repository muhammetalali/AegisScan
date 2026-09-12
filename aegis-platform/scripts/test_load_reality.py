from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location('aegis_load_reality', Path(__file__).with_name('load_reality.py'))
assert _SPEC and _SPEC.loader
load_reality = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = load_reality
_SPEC.loader.exec_module(load_reality)


class _Response:
    status_code = 200


class _FakeAsyncClient:
    calls = 0

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, path):
        type(self).calls += 1
        # Simulate expensive connection/ramp establishment only during the
        # beginning of the stage; steady-state requests are fast.
        await asyncio.sleep(0.025 if type(self).calls <= 4 else 0.001)
        return _Response()


@pytest.mark.asyncio
async def test_stage_warmup_excludes_connection_ramp_from_measured_latency(monkeypatch):
    _FakeAsyncClient.calls = 0
    monkeypatch.setattr(load_reality.httpx, 'AsyncClient', _FakeAsyncClient)

    result = await load_reality.run_stage(
        'http://fixture.invalid',
        ['/health'],
        concurrency=2,
        duration=0.08,
        request_timeout=1.0,
        warmup_seconds=0.08,
    )

    assert result['warmup_seconds'] == 0.08
    assert result['warmup_requests'] >= 4
    assert result['requests'] > 0
    assert result['failures'] == 0
    assert result['error_rate'] == 0.0
    # Cold requests above are ~25ms; the measured steady-state requests should
    # remain far below that because ramp samples are intentionally not counted.
    assert result['latency_ms']['p95'] < 15.0
