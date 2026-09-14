from __future__ import annotations

import pytest
from fastapi import HTTPException

from fastapi_app.routers import ssrf_canary


class FakeRedis:
    def __init__(self):
        self.values = {}
    def delete(self, key):
        self.values.pop(key, None)
    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = (value, ex)
        return True
    def exists(self, key):
        return 1 if key in self.values else 0
    def ttl(self, key):
        return self.values.get(key, ('', 0))[1] or 0
    def close(self):
        return None


def test_canary_control_token_is_required(monkeypatch):
    monkeypatch.delenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', raising=False)
    with pytest.raises(HTTPException) as exc:
        ssrf_canary._require_control('a' * 64)
    assert exc.value.status_code == 503


def test_canary_register_callback_status_roundtrip(monkeypatch):
    store = FakeRedis()
    control = 'b' * 64
    token = 'a' * 64
    monkeypatch.setenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', control)
    monkeypatch.setattr(ssrf_canary, '_client', lambda: store)

    registered = ssrf_canary.register_canary(
        ssrf_canary.CanaryRegistration(token=token),
        x_aegis_canary_control=control,
    )
    assert registered['status'] == 'registered'
    first = ssrf_canary.canary_status(token, x_aegis_canary_control=control)
    assert first['observed'] is False

    callback = ssrf_canary.callback(token)
    assert callback.status_code == 200
    second = ssrf_canary.canary_status(token, x_aegis_canary_control=control)
    assert second['observed'] is True

    assert all(token not in key for key in store.values.keys())
    assert all(token not in str(value) for value in store.values.values())


def test_unknown_callback_is_rejected(monkeypatch):
    store = FakeRedis()
    monkeypatch.setattr(ssrf_canary, '_client', lambda: store)
    with pytest.raises(HTTPException) as exc:
        ssrf_canary.callback('a' * 64)
    assert exc.value.status_code == 404
