from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]


def _load(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = _load("m5_production_preflight", "aegis-platform/scripts/production_preflight.py")
policy = _load("m5_production_policy", "aegis-platform/scripts/production_policy_gate.py")
deploy = _load("m5_production_deploy", "aegis-platform/scripts/production_host_deploy.py")

IMAGE_DIGEST = "sha256:" + "a" * 64
IMMUTABLE_IMAGE = "ghcr.io/aegisscan/kali-recon@" + IMAGE_DIGEST


def _default_kali_environment() -> dict[str, str]:
    return {
        "AEGIS_RECON_PROVIDER": "default-kali",
        "AEGIS_RECON_LEGACY_DISABLED": "true",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
        "AEGIS_KALI_RECON_IMAGE": IMMUTABLE_IMAGE,
        "AEGIS_KALI_RECON_URL": "http://127.0.0.1:18765",
        "AEGIS_KALI_RECON_AUTH_TOKEN": "c" * 64,
        "AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION": "0.1.0",
        "AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT": "d" * 40,
        "AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST": "sha256:" + "e" * 64,
        "AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST": "sha256:" + "f" * 64,
        "AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
        "AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST": "sha256:" + "1" * 64,
    }


def test_default_kali_preflight_requires_complete_immutable_trust_anchor():
    environment = _default_kali_environment()
    failures: list[str] = []
    preflight._check_recon_provider_rollout(environment, failures)
    assert failures == []

    for name in (
        "AEGIS_KALI_RECON_AUTH_TOKEN",
        "AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION",
        "AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT",
        "AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST",
        "AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST",
        "AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST",
        "AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST",
    ):
        broken = dict(environment)
        broken[name] = ""
        failures = []
        preflight._check_recon_provider_rollout(broken, failures)
        assert failures, name

    mutable = dict(environment)
    mutable["AEGIS_KALI_RECON_IMAGE"] = "aegis-kali:recon"
    failures = []
    preflight._check_recon_provider_rollout(mutable, failures)
    assert any("immutable" in item for item in failures)


def test_default_kali_preflight_rejects_raw_kali_and_canary_percentage():
    raw = _default_kali_environment()
    raw["AEGIS_RECON_PROVIDER"] = "kali"
    failures: list[str] = []
    preflight._check_recon_provider_rollout(raw, failures)
    assert "AEGIS_RECON_PROVIDER must be default-kali after M6 legacy Recon retirement" in failures

    stale = _default_kali_environment()
    stale["AEGIS_KALI_RECON_CANARY_BPS"] = "1"
    failures = []
    preflight._check_recon_provider_rollout(stale, failures)
    assert "AEGIS_KALI_RECON_CANARY_BPS must be 0 while AEGIS_RECON_PROVIDER=default-kali" in failures


def test_default_kali_resolved_policy_requires_bound_provider_service():
    environment = _default_kali_environment()
    scanner_env = {
        "AEGIS_RECON_PROVIDER": environment["AEGIS_RECON_PROVIDER"],
        "AEGIS_RECON_LEGACY_DISABLED": "true",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
        "AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
    }

    failures: list[str] = []
    policy._validate_recon_image_binding(
        {"kali_recon": {"image": IMMUTABLE_IMAGE}},
        scanner_env,
        failures,
    )
    assert failures == []

    failures = []
    policy._validate_recon_image_binding({}, scanner_env, failures)
    assert any("requires the kali_recon production service" in item for item in failures)


def test_default_kali_is_the_production_deploy_default_and_activates_profile():
    resolved = deploy._execution_profile_environment({})
    assert resolved["COMPOSE_PROFILES"] == "kali-recon"
    assert deploy._recon_rollout_state(resolved) == ("default-kali", 0)


def test_default_kali_execution_plane_acceptance_proves_routing_and_attestation(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("placeholder=true\n", encoding="utf-8")
    environment = _default_kali_environment()
    environment["COMPOSE_PROFILES"] = "kali-recon"
    calls: list[list[str]] = []

    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"scanner_worker", "kali_recon"})
    monkeypatch.setattr(
        deploy,
        "_run",
        lambda argv, **kwargs: calls.append(list(argv)) or SimpleNamespace(stdout="", returncode=0),
    )
    monkeypatch.setattr(deploy.time, "sleep", lambda *_: None)

    deploy._execution_plane_acceptance(env_file, environment, attempts=1)
    assert calls
    command = " ".join(calls[-1])
    assert "scanner_worker" in command
    assert "'recon.fierce'" in command
    assert "'recon.dnsenum'" in command
    assert "'recon.subfinder'" in command
    assert "'recon.amass'" in command
    assert "default-kali-parity-approved" in command
    assert "capability-not-parity-approved" not in command
    assert "_preflight_runtime_attestation" in command
    assert "legacy_recon_disabled" in command

    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"scanner_worker"})
    with pytest.raises(deploy.DeployError, match="kali_recon"):
        deploy._execution_plane_acceptance(env_file, environment, attempts=1)


def test_default_kali_rollback_preserves_previous_governed_provider_profile():
    environment = _default_kali_environment()
    environment["COMPOSE_PROFILES"] = "monitoring,kali-recon"
    rollback = deploy._rollback_execution_environment(environment)
    assert rollback["AEGIS_RECON_PROVIDER"] == "default-kali"
    assert rollback["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
    assert set(rollback["COMPOSE_PROFILES"].split(",")) == {"monitoring", "kali-recon"}
