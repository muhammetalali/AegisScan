from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
from aegis.core.plugin_registry import PluginMetadata, PluginRegistry
from aegis.engines.validation_platform.defensive_simulation import (
    DefensiveAdversarySimulator,
)


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if not self.payload:
            return b""
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk


def test_verified_plugin_sync_downloads_only_enabled_https_entries(
    tmp_path, monkeypatch
) -> None:
    payload_buffer = io.BytesIO()
    with zipfile.ZipFile(payload_buffer, "w") as archive:
        archive.writestr("plugin.json", '{"name": "demo"}')
    payload = payload_buffer.getvalue()
    registry = PluginRegistry()
    registry._plugins["demo"] = PluginMetadata(
        name="demo",
        version="1.0.0",
        source_url="https://example.test/demo.zip",
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    monkeypatch.setattr(
        "aegis.core.plugin_registry.urlopen", lambda *args, **kwargs: _Response(payload)
    )

    downloaded = registry.sync_verified({}, tmp_path)

    assert downloaded["demo"].joinpath("plugin.json").read_text() == '{"name": "demo"}'


def test_plugin_download_rejects_missing_hash_and_insecure_url(tmp_path) -> None:
    registry = PluginRegistry()
    registry._plugins["insecure"] = PluginMetadata(
        name="insecure", version="1.0.0", source_url="http://example.test/a.zip"
    )

    with pytest.raises(ValueError, match="HTTPS"):
        registry.download_verified("insecure", tmp_path)


def test_plugin_archive_rejects_path_traversal(tmp_path) -> None:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../outside.txt", "blocked")
    with zipfile.ZipFile(io.BytesIO(payload.getvalue())) as archive:
        with pytest.raises(ValueError, match="unsafe path"):
            PluginRegistry._safe_extract(archive, tmp_path / "plugin")


def test_defensive_simulation_reports_control_gaps_without_execution() -> None:
    result = DefensiveAdversarySimulator().simulate(
        ["credential-abuse", "data-egress"],
        {"mfa": True, "identity-monitoring": True, "rate-limiting": True, "dlp": True},
    )

    assert result.observations[0].detected is True
    assert result.observations[1].detected is False
    assert result.gaps == ["data-egress"]
    assert "egress-firewall" in " ".join(result.recommendations)
