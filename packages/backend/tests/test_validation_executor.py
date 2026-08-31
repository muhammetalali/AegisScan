from __future__ import annotations

import pytest

from fastapi_app.services.validation_executor import _connect_target


def test_non_containerized_loopback_target_is_unchanged(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTAINERIZED", "0")
    target = "http://127.0.0.1:5173/dashboard"

    connection_target, original = _connect_target(target)

    assert connection_target == target
    assert original is None


def test_containerized_loopback_target_uses_host_gateway(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTAINERIZED", "1")
    monkeypatch.setenv("AEGIS_HOST_GATEWAY", "host.docker.internal")
    target = "http://127.0.0.1:5173/dashboard"

    connection_target, original = _connect_target(target)

    assert connection_target == "http://host.docker.internal:5173/dashboard"
    assert original == target


def test_containerized_localhost_preserves_path_query_and_port(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTAINERIZED", "true")
    monkeypatch.setenv("AEGIS_HOST_GATEWAY", "host-gateway.internal")
    target = "https://localhost:8443/api/health?check=1"

    connection_target, original = _connect_target(target)

    assert connection_target == "https://host-gateway.internal:8443/api/health?check=1"
    assert original == target


def test_embedded_target_credentials_are_rejected(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTAINERIZED", "1")

    with pytest.raises(ValueError, match="Credentials embedded"):
        _connect_target("http://user:password@localhost:5173/")
