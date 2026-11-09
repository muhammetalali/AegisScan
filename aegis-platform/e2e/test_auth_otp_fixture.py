"""Distinct MFA regression fixture: vulnerable versus patched, entirely in-process."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

_ROOT = Path(__file__).resolve().parent
_MOD = _ROOT / "fixtures/auth-otp-target/app.py"
spec = importlib.util.spec_from_file_location("aegis_local_auth_otp_fixture", _MOD)
fixture = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixture
spec.loader.exec_module(fixture)


def client(mode: str) -> TestClient:
    return TestClient(fixture.create_app(mode), base_url="https://local-fixture.invalid")


def login(c: TestClient) -> None:
    r = c.post("/api/login", json={"username": "local-tester", "password": "local-lab-secret"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "redirect": "/otp"}
    assert "fixture_sid=" in r.headers["set-cookie"]
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "secure" in r.headers["set-cookie"].lower()


@pytest.mark.parametrize("mode", ["vulnerable", "patched"])
def test_anonymous_denied_even_in_weak_mode(mode):
    with client(mode) as c:
        r = c.get("/protected")
        assert r.status_code == 401
        assert "LOCAL_FIXTURE_SUCCESS" not in r.text
        assert c.post("/api/otp", json={"code": "246810"}).status_code == 403


@pytest.mark.parametrize("mode", ["vulnerable", "patched"])
def test_wrong_password_never_creates_session(mode):
    with client(mode) as c:
        r = c.post("/api/login", json={"username": "local-tester", "password": "nope"})
        assert r.status_code == 401
        assert "set-cookie" not in r.headers
        assert c.get("/protected").status_code == 401


@pytest.mark.parametrize(
    "mode,expected_code,expected_marker",
    [("vulnerable", 200, True), ("patched", 403, False)],
)
def test_primary_auth_without_otp_distinguishes_vulnerable_and_patched(mode, expected_code, expected_marker):
    with client(mode) as c:
        login(c)
        r = c.get("/protected")
        assert r.status_code == expected_code
        assert ("LOCAL_FIXTURE_SUCCESS" in r.text) is expected_marker


@pytest.mark.parametrize("mode", ["vulnerable", "patched"])
def test_authorized_two_stage_sequence_reaches_protected(mode):
    with client(mode) as c:
        login(c)
        assert c.get("/otp").status_code == 200
        denied = c.post("/api/otp", json={"code": "111111"})
        assert denied.status_code == 401
        assert c.post("/api/otp", json={"code": "246810"}).json() == {
            "ok": True, "redirect": "/protected",
        }
        success = c.get("/protected")
        assert success.status_code == 200
        assert "LOCAL_FIXTURE_SUCCESS" in success.text


def test_two_browser_contexts_never_share_authentication_state():
    app = fixture.create_app("patched")
    with TestClient(app, base_url="https://local-fixture.invalid") as first:
        with TestClient(app, base_url="https://local-fixture.invalid") as second:
            login(first)
            assert second.get("/protected").status_code == 401
            assert first.get("/protected").status_code == 403
            assert second.post("/api/otp", json={"code": "246810"}).status_code == 403
            first.post("/api/otp", json={"code": "246810"})
            assert first.get("/protected").status_code == 200
            assert second.get("/protected").status_code == 401


def test_fixture_incompatible_modes_fail_closed():
    for mode in ("", "fixed", "debug", "production"):
        with pytest.raises(ValueError):
            fixture.create_app(mode)


def test_fixture_api_input_is_strict_and_does_not_expose_schema():
    with client("patched") as c:
        assert c.get("/openapi.json").status_code == 404
        bad = c.post("/api/login", json={
            "username": "local-tester", "password": "local-lab-secret", "admin": True,
        })
        assert bad.status_code == 422
        assert "set-cookie" not in bad.headers


def test_contract_observes_patched_fixture_without_marking_external_lab_solved():
    # The contract can evaluate real in-process responses; it never reaches
    # a deployed challenge, bypasses provider approval, or manufactures a screenshot.
    backend = _ROOT.parent / "backend/fastapi_app/services/auth_otp_lab_contract.py"
    s = importlib.util.spec_from_file_location("auth_otp_fixture_contract", backend)
    auth = importlib.util.module_from_spec(s)
    sys.modules[s.name] = auth
    s.loader.exec_module(auth)
    with client("patched") as c:
        attempt = auth.AuthAttempt(
            attempt_ref=str(uuid4()),
            authorized_origin="https://local-fixture.invalid",
        )
        login_page = c.get("/login")
        attempt, _ = auth.observe(
            attempt, step="login_form",
            http_status=login_page.status_code, body=login_page.content,
        )
        login_response = c.post("/api/login", json={
            "username": "local-tester", "password": "local-lab-secret",
        })
        worker_session_ref = str(uuid4())
        attempt, _ = auth.observe(
            attempt, step="primary_login", http_status=login_response.status_code,
            body=login_response.content, session_binding_ref=worker_session_ref,
        )
        assert attempt.stage == auth.Stage.OTP_PENDING
        assert c.get("/protected").status_code == 403
        otp_response = c.post("/api/otp", json={"code": "246810"})
        attempt, _ = auth.observe(
            attempt, step="otp_submit", http_status=otp_response.status_code,
            body=otp_response.content, session_binding_ref=worker_session_ref,
        )
        response = c.get("/protected")
        attempt, summary = auth.observe(
            attempt, step="protected_fetch", request_path="/protected",
            http_status=response.status_code, body=response.content,
            session_binding_ref=worker_session_ref,
        )
        assert attempt.stage == auth.Stage.PROTECTED_OBSERVED
        assert summary["lab_solved"] is False
        assert summary["independent_success_screen_proven"] is False
        assert "fixture_sid" not in str(summary)
