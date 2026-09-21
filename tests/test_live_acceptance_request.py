from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "aegis-platform" / "scripts" / "live_acceptance_request.py"
SPEC = importlib.util.spec_from_file_location("live_acceptance_request", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

authorize = MODULE.authorize
LiveAcceptanceRequestError = MODULE.LiveAcceptanceRequestError

BASE = "1" * 40
HEAD = "2" * 40
NOW = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)


def _request(tmp_path: Path, **overrides) -> Path:
    payload = {
        "schema": "aegisscan.live-acceptance-request.v1",
        "request_id": "cloud-live-20260921-v1",
        "scope": "cloud-providers",
        "confirm": "VALIDATE",
        "requested_branch": "main",
        "requested_base_sha": BASE,
        "requested_at": "2026-09-21T11:00:00Z",
        "expires_at": "2026-09-22T10:59:59Z",
    }
    payload.update(overrides)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _authorize(path: Path, **overrides):
    kwargs = {
        "event_name": "push",
        "ref": "refs/heads/main",
        "current_sha": HEAD,
        "event_before": BASE,
        "confirm": "",
        "request_file": path,
        "scope": "cloud-providers",
        "required_confirm": "VALIDATE",
        "now": NOW,
    }
    kwargs.update(overrides)
    return authorize(**kwargs)


def test_push_authorized(tmp_path):
    result = _authorize(_request(tmp_path))
    assert result["authorized"] is True
    assert result["authorization_mode"] == "one-time-main-push"
    assert result["requested_base_sha"] == BASE


def test_manual_authorized(tmp_path):
    result = authorize(
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        current_sha=HEAD,
        event_before="",
        confirm="VALIDATE",
        request_file=tmp_path / "unused.json",
        scope="cloud-providers",
        required_confirm="VALIDATE",
        now=NOW,
    )
    assert result["authorization_mode"] == "workflow_dispatch"


@pytest.mark.parametrize(
    "overrides",
    [
        {"requested_base_sha": "3" * 40},
        {"expires_at": "2026-09-21T11:59:59Z"},
        {"scope": "identity"},
        {"extra": "unexpected"},
    ],
)
def test_push_rejects_invalid_request(tmp_path, overrides):
    with pytest.raises(LiveAcceptanceRequestError):
        _authorize(_request(tmp_path, **overrides))
