import importlib.util
import os
from pathlib import Path

import pytest

RUNNER = Path(__file__).parents[1] / "runner" / "runner.py"
spec = importlib.util.spec_from_file_location("aegis_kali_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(runner)


def valid_manifest():
    return {
        "execution_id": "exec-1",
        "capability_id": "web.content-discovery",
        "asset_id": "asset-1",
        "authorization_id": "auth-1",
        "authorization_decision": "authorized",
        "risk_level": "active-low",
        "profile": "base",
        "options": {},
    }


def test_accepts_complete_authorized_contract(monkeypatch):
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "base")
    runner._validate_manifest(valid_manifest())


@pytest.mark.parametrize("field", ["execution_id", "capability_id", "asset_id", "authorization_id"])
def test_rejects_missing_bindings(field):
    payload = valid_manifest()
    payload.pop(field)
    with pytest.raises(ValueError):
        runner._validate_manifest(payload)


def test_rejects_non_authorized_decision():
    payload = valid_manifest()
    payload["authorization_decision"] = "denied"
    with pytest.raises(ValueError, match="not authorized"):
        runner._validate_manifest(payload)


@pytest.mark.parametrize("field", ["command", "cmd", "shell", "argv", "binary", "executable"])
def test_rejects_arbitrary_execution_fields(field):
    payload = valid_manifest()
    payload[field] = "id"
    with pytest.raises(ValueError, match="forbidden"):
        runner._validate_manifest(payload)


def test_rejects_profile_mismatch(monkeypatch):
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "recon")
    with pytest.raises(ValueError, match="profile binding mismatch"):
        runner._validate_manifest(valid_manifest())


def test_rejects_unknown_risk_level():
    payload = valid_manifest()
    payload["risk_level"] = "unbounded"
    with pytest.raises(ValueError, match="unsupported risk level"):
        runner._validate_manifest(payload)
