from __future__ import annotations

import http.client
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "scripts/ci/wait_for_required_ci.py"
SPEC = importlib.util.spec_from_file_location("wait_for_required_ci", PATH)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

SHA = "a" * 40


def _payload(*runs):
    return {"workflow_runs": list(runs)}


def _run(**changes):
    payload = {
        "id": 10,
        "name": "Required CI Governance",
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
    }
    payload.update(changes)
    return payload


def test_selects_latest_exact_sha_main_push_run():
    selected = gate._select_run(
        _payload(
            _run(id=8, run_attempt=1),
            _run(id=9, run_attempt=2),
            _run(id=11, head_sha="b" * 40),
        ),
        sha=SHA,
        branch="main",
        workflow_name="Required CI Governance",
        event="push",
    )
    assert selected["id"] == 9


def test_wait_returns_only_completed_success(monkeypatch):
    responses = iter(
        [
            _payload(_run(status="in_progress", conclusion=None)),
            _payload(_run(status="completed", conclusion="success", id=12)),
        ]
    )
    monkeypatch.setattr(gate, "_live_branch_sha", lambda *_args, **_kwargs: SHA)
    monkeypatch.setattr(gate, "_api_json", lambda *_args, **_kwargs: next(responses))
    ticks = iter([0.0, 0.0, 1.0, 1.0, 2.0])
    monkeypatch.setattr(gate.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(gate.time, "sleep", lambda _seconds: None)

    result = gate.wait_for_required_ci(
        repo="owner/repo",
        token="token",
        sha=SHA,
        branch="main",
        workflow_name="Required CI Governance",
        event="push",
        timeout_seconds=10,
        poll_seconds=1,
    )
    assert result["status"] == "success"
    assert result["run_id"] == 12
    assert result["release_sha"] == SHA


def test_wait_fails_closed_on_unsuccessful_terminal_run(monkeypatch):
    monkeypatch.setattr(gate, "_live_branch_sha", lambda *_args, **_kwargs: SHA)
    monkeypatch.setattr(
        gate,
        "_api_json",
        lambda *_args, **_kwargs: _payload(_run(conclusion="failure")),
    )
    monkeypatch.setattr(gate.time, "monotonic", lambda: 0.0)
    with pytest.raises(gate.RequiredCIGateError, match="completed without success"):
        gate.wait_for_required_ci(
            repo="owner/repo",
            token="token",
            sha=SHA,
            branch="main",
            workflow_name="Required CI Governance",
            event="push",
            timeout_seconds=10,
            poll_seconds=1,
        )


def test_wait_rejects_invalid_sha_without_api_call(monkeypatch):
    monkeypatch.setattr(
        gate,
        "_api_json",
        lambda *_args, **_kwargs: pytest.fail("API must not be called"),
    )
    with pytest.raises(gate.RequiredCIGateError, match="40 lowercase hexadecimal"):
        gate.wait_for_required_ci(
            repo="owner/repo",
            token="token",
            sha="bad",
            branch="main",
            workflow_name="Required CI Governance",
            event="push",
            timeout_seconds=10,
            poll_seconds=1,
        )


def test_wait_fails_if_live_main_moves_during_poll(monkeypatch):
    monkeypatch.setattr(gate, "_live_branch_sha", lambda *_args, **_kwargs: "b" * 40)
    monkeypatch.setattr(
        gate,
        "_api_json",
        lambda *_args, **_kwargs: pytest.fail("workflow API must not be queried after main moved"),
    )
    monkeypatch.setattr(gate.time, "monotonic", lambda: 0.0)
    with pytest.raises(gate.RequiredCIGateError, match="live branch main moved"):
        gate.wait_for_required_ci(
            repo="owner/repo",
            token="token",
            sha=SHA,
            branch="main",
            workflow_name="Required CI Governance",
            event="push",
            timeout_seconds=10,
            poll_seconds=1,
        )


def test_live_execution_workflows_remain_lifecycle_only_to_avoid_ci_barrier_deadlock():
    policy = json.loads(
        (ROOT / ".github/governance/required-ci-policy.json").read_text(encoding="utf-8")
    )
    lifecycle = set(policy["lifecycle_only_workflows"])
    assert {
        "Cloud Live Provider Reality",
        "External Identity Live Provider Reality",
        "Internal Production Deploy and Acceptance",
    } <= lifecycle



class _JSONResponse:
    def __init__(self, payload: bytes | None = None, error: BaseException | None = None):
        self.payload = payload
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args, **_kwargs):
        if self.error is not None:
            raise self.error
        return self.payload or b""


def test_api_json_retries_incomplete_read_then_succeeds(monkeypatch):
    responses = iter(
        [
            _JSONResponse(error=http.client.IncompleteRead(b'{"workflow_runs":', 10)),
            _JSONResponse(payload=b'{"workflow_runs": []}'),
        ]
    )
    monkeypatch.setattr(gate.urllib.request, "urlopen", lambda *_args, **_kwargs: next(responses))
    sleeps = []
    monkeypatch.setattr(gate.time, "sleep", lambda seconds: sleeps.append(seconds))

    payload = gate._api_json(
        "/repos/owner/repo/actions/runs",
        "token",
        max_attempts=3,
        retry_base_seconds=0.25,
    )

    assert payload == {"workflow_runs": []}
    assert sleeps == [0.25]


def test_api_json_retries_transient_http_but_fails_closed_on_permanent_http(monkeypatch):
    transient = gate.urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=503,
        msg="Service Unavailable",
        hdrs={},
        fp=None,
    )
    permanent = gate.urllib.error.HTTPError(
        url="https://api.github.com/test",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=None,
    )
    responses = iter([transient, _JSONResponse(payload=b'{"ok": true}')])

    def transient_then_success(*_args, **_kwargs):
        item = next(responses)
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(gate.urllib.request, "urlopen", transient_then_success)
    monkeypatch.setattr(gate.time, "sleep", lambda _seconds: None)
    assert gate._api_json("/test", "token", max_attempts=2, retry_base_seconds=0)["ok"] is True

    monkeypatch.setattr(
        gate.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(permanent),
    )
    with pytest.raises(gate.RequiredCIGateError, match="HTTP 403"):
        gate._api_json("/test", "token", max_attempts=3, retry_base_seconds=0)


def test_api_json_exhausts_transient_transport_retries(monkeypatch):
    monkeypatch.setattr(
        gate.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            http.client.RemoteDisconnected("peer closed connection")
        ),
    )
    monkeypatch.setattr(gate.time, "sleep", lambda _seconds: None)

    with pytest.raises(gate.RequiredCIGateError, match="after 3 attempts"):
        gate._api_json("/test", "token", max_attempts=3, retry_base_seconds=0)
