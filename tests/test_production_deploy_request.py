import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_deploy_request.py"
SPEC = importlib.util.spec_from_file_location("production_deploy_request", PATH)
assert SPEC and SPEC.loader
request = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(request)

NOW = datetime(2026, 9, 17, 15, 0, tzinfo=timezone.utc)
BASE = "a" * 40
HEAD = "b" * 40


def _request(path: Path, **changes) -> Path:
    payload = {
        "schema": "aegisscan.internal-production-deployment-request.v1",
        "request_id": "a03-live-20260917",
        "confirm": "DEPLOY",
        "deployment_mode": "internal",
        "requested_branch": "main",
        "requested_base_sha": BASE,
        "requested_at": "2026-09-17T14:30:00Z",
        "expires_at": "2026-09-18T02:30:00Z",
    }
    payload.update(changes)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_manual_dispatch_is_explicit_main_only(tmp_path: Path):
    result = request.authorize(
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        current_sha=HEAD,
        event_before="",
        confirm="DEPLOY",
        request_file=tmp_path / "unused.json",
        now=NOW,
    )
    assert result["authorized"] is True
    assert result["authorization_mode"] == "workflow_dispatch"
    assert result["release_sha"] == HEAD

    with pytest.raises(request.DeployRequestError, match="confirm=DEPLOY"):
        request.authorize(
            event_name="workflow_dispatch",
            ref="refs/heads/main",
            current_sha=HEAD,
            event_before="",
            confirm="deploy",
            request_file=tmp_path / "unused.json",
            now=NOW,
        )


def test_one_time_push_is_bound_to_exact_previous_main_and_expiry(tmp_path: Path):
    path = _request(tmp_path / "request.json")
    result = request.authorize(
        event_name="push",
        ref="refs/heads/main",
        current_sha=HEAD,
        event_before=BASE,
        confirm="",
        request_file=path,
        now=NOW,
    )
    assert result["authorized"] is True
    assert result["authorization_mode"] == "one-time-main-push"
    assert result["requested_base_sha"] == BASE
    assert result["release_sha"] == HEAD

    with pytest.raises(request.DeployRequestError, match="base SHA"):
        request.authorize(
            event_name="push",
            ref="refs/heads/main",
            current_sha=HEAD,
            event_before="c" * 40,
            confirm="",
            request_file=path,
            now=NOW,
        )


def test_rejects_expired_overlong_unknown_or_nonmain_requests(tmp_path: Path):
    expired = _request(tmp_path / "expired.json", expires_at="2026-09-17T14:59:59Z")
    with pytest.raises(request.DeployRequestError, match="expired"):
        request.authorize(
            event_name="push", ref="refs/heads/main", current_sha=HEAD, event_before=BASE,
            confirm="", request_file=expired, now=NOW,
        )

    long_lived = _request(
        tmp_path / "long.json",
        requested_at="2026-09-17T00:00:00Z",
        expires_at="2026-09-18T00:00:01Z",
    )
    with pytest.raises(request.DeployRequestError, match="24 hours"):
        request.authorize(
            event_name="push", ref="refs/heads/main", current_sha=HEAD, event_before=BASE,
            confirm="", request_file=long_lived, now=NOW,
        )

    payload = json.loads(_request(tmp_path / "unknown.json").read_text())
    payload["extra"] = True
    (tmp_path / "unknown.json").write_text(json.dumps(payload))
    with pytest.raises(request.DeployRequestError, match="fields mismatch"):
        request.authorize(
            event_name="push", ref="refs/heads/main", current_sha=HEAD, event_before=BASE,
            confirm="", request_file=tmp_path / "unknown.json", now=NOW,
        )

    with pytest.raises(request.DeployRequestError, match="refs/heads/main"):
        request.authorize(
            event_name="push", ref="refs/heads/feature", current_sha=HEAD, event_before=BASE,
            confirm="", request_file=_request(tmp_path / "branch.json"), now=NOW,
        )
