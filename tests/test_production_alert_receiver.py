from __future__ import annotations

import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "aegis-platform/scripts/production_alert_receiver.py"
SPEC = importlib.util.spec_from_file_location("production_alert_receiver", SCRIPT)
assert SPEC and SPEC.loader
receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)


def _token(tmp_path: Path) -> Path:
    path = tmp_path / "token"
    path.write_text("t" * 64 + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _server(tmp_path: Path):
    state = receiver.ReceiverState(receiver._private_token(_token(tmp_path)), tmp_path / "audit" / "events.jsonl")
    receiver.Receiver.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), receiver.Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state


def _request(url: str, *, data: bytes | None = None, token: str = "", content_type: str = "application/json"):
    headers = {"Content-Type": content_type}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=3)


def test_receiver_requires_private_token_file(tmp_path: Path):
    token = _token(tmp_path)
    assert receiver._private_token(token) == b"t" * 64
    token.chmod(0o644)
    with pytest.raises(receiver.ReceiverConfigError, match="0600"):
        receiver._private_token(token)


def test_receiver_converts_token_io_failure_to_structured_config_error(tmp_path: Path, monkeypatch):
    token = _token(tmp_path)

    def unreadable(_self):
        raise PermissionError("synthetic token read denial")

    monkeypatch.setattr(receiver.Path, "read_bytes", unreadable)
    with pytest.raises(receiver.ReceiverConfigError, match="not readable"):
        receiver._private_token(token)


def test_receiver_rejects_unauthorized_and_records_minimal_authenticated_audit(tmp_path: Path):
    server, thread, state = _server(tmp_path)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    payload = {
        "receiver": "aegis-production",
        "status": "firing",
        "alerts": [{
            "labels": {
                "alertname": "AegisCritical",
                "service": "aegisscan",
                "severity": "critical",
                "release_sha": "a" * 40,
                "acceptance_id": "c" * 32,
            },
            "annotations": {"summary": "do-not-persist-this-secret-value"},
        }],
    }
    raw = json.dumps(payload).encode("utf-8")
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _request(base + "/alert", data=raw)
        assert exc.value.code == 401
        assert state.unauthorized_total == 1

        with _request(base + "/alert", data=raw, token="t" * 64) as response:
            assert response.status == 202

        audit_path = tmp_path / "audit" / "events.jsonl"
        audit = audit_path.read_text(encoding="utf-8")
        assert audit_path.stat().st_mode & 0o777 == 0o600
        record = json.loads(audit.strip())
        assert record["schema"] == "aegisscan.alert-receiver-event.v1"
        assert record["alertnames"] == ["AegisCritical"]
        assert record["severities"] == ["critical"]
        assert record["release_shas"] == ["a" * 40]
        assert record["acceptance_ids"] == ["c" * 32]
        assert len(record["payload_sha256"]) == 64
        assert "do-not-persist-this-secret-value" not in audit

        with urllib.request.urlopen(base + "/metrics", timeout=3) as response:
            metrics = response.read().decode("utf-8")
        assert "aegis_alert_receiver_events_total 1" in metrics
        assert "aegis_alert_receiver_unauthorized_total 1" in metrics
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_receiver_rejects_non_json_and_empty_alerts(tmp_path: Path):
    server, thread, _state = _server(tmp_path)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _request(base + "/alert", data=b"not-json", token="t" * 64)
        assert exc.value.code == 400
        with pytest.raises(urllib.error.HTTPError) as exc:
            _request(base + "/alert", data=b'{"alerts":[]}', token="t" * 64)
        assert exc.value.code == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_receiver_rotates_bounded_audit_log(tmp_path: Path, monkeypatch):
    token = receiver._private_token(_token(tmp_path))
    audit = tmp_path / "audit" / "events.jsonl"
    state = receiver.ReceiverState(token, audit)
    monkeypatch.setattr(receiver, "MAX_AUDIT_BYTES", 400)
    payload = {
        "receiver": "aegis-production",
        "status": "firing",
        "alerts": [{"labels": {"alertname": "AegisBoundedAudit", "severity": "critical"}}],
    }
    raw = json.dumps(payload).encode("utf-8")
    state.record(payload, raw)
    state.record(payload, raw)
    assert audit.is_file()
    rotated = audit.with_name(audit.name + ".1")
    assert rotated.is_file()
    assert audit.stat().st_mode & 0o777 == 0o600
    assert rotated.stat().st_mode & 0o777 == 0o600
    assert audit.stat().st_size <= receiver.MAX_AUDIT_BYTES
