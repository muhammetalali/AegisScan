import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/public_acceptance.py"
SPEC = importlib.util.spec_from_file_location("public_acceptance", PATH)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def test_origin_requires_verified_public_https():
    assert acceptance._origin("https://security.example.com", False) == "https://security.example.com"
    with pytest.raises(acceptance.AcceptanceError):
        acceptance._origin("http://security.example.com", False)
    with pytest.raises(acceptance.AcceptanceError):
        acceptance._origin("https://localhost", False)
    assert acceptance._origin("https://localhost:8443", True) == "https://localhost:8443"


def test_validate_requires_health_ready_frontend_and_security_headers(monkeypatch):
    headers = {name: "present" for name in acceptance.REQUIRED_SECURITY_HEADERS}
    headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"

    def fake_request(origin, path):
        body = b'{"status":"ok"}' if path in {"/health", "/ready"} else b"<html></html>"
        return 200, headers, body

    monkeypatch.setattr(acceptance, "_request", fake_request)
    result = acceptance.validate("https://security.example.com")
    assert result["status"] == "success"
    assert result["checks"]["verified_https"] is True


def test_validate_rejects_missing_security_headers(monkeypatch):
    def fake_request(origin, path):
        return 200, {"strict-transport-security": "max-age=31536000"}, b'{"status":"ok"}'

    monkeypatch.setattr(acceptance, "_request", fake_request)
    with pytest.raises(acceptance.AcceptanceError, match="missing required security headers"):
        acceptance.validate("https://security.example.com")
