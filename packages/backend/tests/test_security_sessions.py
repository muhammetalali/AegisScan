from fastapi import FastAPI

from fastapi_app.routers.security_sessions import router
from fastapi_app.services.security_sessions import (
    ALLOWED_CAPABILITIES,
    redact,
    _validate_capabilities,
    _validate_scope,
)


def test_scope_requires_explicit_boundary():
    normalized = _validate_scope({"targets": ["10.10.0.10"], "ports": [443]})
    assert normalized["boundary"] == "explicit"
    assert normalized["targets"] == ["10.10.0.10"]


def test_scope_rejects_empty_target_set():
    try:
        _validate_scope({"targets": [], "asset_ids": []})
    except ValueError as exc:
        assert "at least one target" in str(exc)
    else:
        raise AssertionError("empty scope must be rejected")


def test_unknown_capability_is_rejected():
    class User:
        is_staff = False
        is_superuser = False

    try:
        _validate_capabilities(["not-a-real-capability"], None, User())
    except ValueError as exc:
        assert "unsupported capabilities" in str(exc)
    else:
        raise AssertionError("unknown capability must be rejected")


def test_high_risk_capability_requires_approval_and_staff():
    class NonStaff:
        is_staff = False
        is_superuser = False

    class Staff:
        is_staff = True
        is_superuser = False

    for approval_id, user in ((None, Staff()), ("approval-1", NonStaff())):
        try:
            _validate_capabilities(["interactive_session"], approval_id, user)
        except PermissionError as exc:
            assert "require" in str(exc)
        except ValueError as exc:
            assert "require approval_id" in str(exc)
        else:
            raise AssertionError("high-risk capability must be gated")

    assert "interactive_session" in ALLOWED_CAPABILITIES
    assert _validate_capabilities(["interactive_session"], "approval-1", Staff()) == ["interactive_session"]


def test_sensitive_evidence_is_redacted():
    payload = redact({
        "token": "secret",
        "nested": {"password": "secret", "safe": "ok"},
        "items": [{"api_key": "secret"}],
    })
    assert payload["token"] == "[REDACTED]"
    assert payload["nested"]["password"] == "[REDACTED]"
    assert payload["nested"]["safe"] == "ok"
    assert payload["items"][0]["api_key"] == "[REDACTED]"


def test_security_session_routes_are_mounted():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    paths = {route.path for route in app.routes}
    assert "/api/v1/security-sessions" in paths
    assert "/api/v1/security-sessions/{session_id}/evidence" in paths
    assert "/api/v1/security-sessions/{session_id}/identity/revoke" in paths
    assert "/api/v1/security-sessions/{session_id}/cleanup/verify" in paths
