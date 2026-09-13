import importlib.util
import json
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


def test_rejects_unknown_top_level_field():
    payload = valid_manifest()
    payload["unexpected"] = True
    with pytest.raises(ValueError, match="unknown top-level field"):
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


def test_load_manifest_returns_exact_bytes_that_were_parsed(tmp_path):
    path = tmp_path / "job.json"
    raw = (json.dumps(valid_manifest(), separators=(",", ":")) + "\n").encode()
    path.write_bytes(raw)
    payload, loaded = runner._load_manifest(path)
    assert payload == valid_manifest()
    assert loaded == raw


def test_load_manifest_rejects_oversize_before_unbounded_read(tmp_path):
    path = tmp_path / "job.json"
    path.write_bytes(b"x" * (runner.MAX_MANIFEST_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds size limit"):
        runner._load_manifest(path)


def test_load_manifest_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "job.json"
    path.write_text(
        '{"execution_id":"one","execution_id":"two","capability_id":"c","asset_id":"a",'
        '"authorization_id":"auth","authorization_decision":"authorized","risk_level":"passive",'
        '"profile":"base","options":{}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: execution_id"):
        runner._load_manifest(path)


def test_load_manifest_rejects_symlink_input(tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(valid_manifest()), encoding="utf-8")
    link = tmp_path / "job.json"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="missing or unsafe"):
        runner._load_manifest(link)


def test_main_does_not_reopen_job_manifest(tmp_path, monkeypatch, capsys):
    job = tmp_path / "job.json"
    job.write_text(json.dumps(valid_manifest()), encoding="utf-8")
    runtime_path = tmp_path / "runtime-manifest.json"
    runtime_path.write_text(json.dumps(valid_runtime_manifest()), encoding="utf-8")

    monkeypatch.setenv("AEGIS_JOB_MANIFEST", str(job))
    monkeypatch.setenv("AEGIS_RUNNER_VERSION", "0.1.0")
    monkeypatch.setenv("AEGIS_RUNNER_PROFILE", "base")
    monkeypatch.setenv("AEGIS_BASE_IMAGE_DIGEST", "sha256:base")
    monkeypatch.setenv("AEGIS_BUILD_COMMIT", "commit-1")
    monkeypatch.setattr(runner, "RUNTIME_MANIFEST_PATH", runtime_path)

    original_load = runner._load_manifest
    calls = 0

    def load_once(path):
        nonlocal calls
        calls += 1
        payload, raw = original_load(path)
        os.unlink(path)
        return payload, raw

    monkeypatch.setattr(runner, "_load_manifest", load_once)
    assert runner.main() == 0
    assert calls == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "accepted-no-dispatch"


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
