import importlib.util
import json
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


def valid_runtime_manifest():
    return {
        "runtime": "aegis-kali",
        "runner_version": "0.1.0",
        "profile": "base",
        "base_image_digest": "sha256:base",
        "build_commit": "commit-1",
        "foundation_packages": {"python3": "3.14.6-1"},
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


def test_runtime_manifest_is_bound_to_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_RUNNER_VERSION", "0.1.0")
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "base")
    monkeypatch.setenv("AEGIS_BASE_IMAGE_DIGEST", "sha256:base")
    monkeypatch.setenv("AEGIS_BUILD_COMMIT", "commit-1")
    path = tmp_path / "runtime-manifest.json"
    path.write_text(json.dumps(valid_runtime_manifest()), encoding="utf-8")
    payload, raw = runner._load_runtime_manifest(path)
    assert payload["profile"] == "base"
    assert raw


@pytest.mark.parametrize("field,value", [("profile", "recon"), ("build_commit", "wrong"), ("base_image_digest", "sha256:wrong")])
def test_runtime_manifest_rejects_binding_mismatch(tmp_path, monkeypatch, field, value):
    monkeypatch.setenv("AEGIS_RUNNER_VERSION", "0.1.0")
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "base")
    monkeypatch.setenv("AEGIS_BASE_IMAGE_DIGEST", "sha256:base")
    monkeypatch.setenv("AEGIS_BUILD_COMMIT", "commit-1")
    payload = valid_runtime_manifest()
    payload[field] = value
    path = tmp_path / "runtime-manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="runtime manifest binding mismatch"):
        runner._load_runtime_manifest(path)


def test_runtime_provenance_records_runtime_manifest_digest(monkeypatch):
    monkeypatch.setenv("AEGIS_RUNNER_VERSION", "0.1.0")
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "base")
    monkeypatch.setenv("AEGIS_BASE_IMAGE_DIGEST", "sha256:base")
    monkeypatch.setenv("AEGIS_BUILD_COMMIT", "commit-1")
    result = runner._runtime_provenance(valid_manifest(), b"{}", b'{"runtime":"aegis-kali"}\n')
    assert result["runtime_manifest_digest"].startswith("sha256:")
    assert result["base_image_digest"] == "sha256:base"
