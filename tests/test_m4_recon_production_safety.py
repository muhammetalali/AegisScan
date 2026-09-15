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


preflight = _load("m4_production_preflight", "aegis-platform/scripts/production_preflight.py")
policy = _load("m4_production_policy", "aegis-platform/scripts/production_policy_gate.py")
deploy = _load("m4_production_deploy", "aegis-platform/scripts/production_host_deploy.py")

IMAGE_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMMUTABLE_IMAGE = "ghcr.io/aegisscan/kali-recon@" + IMAGE_DIGEST


def _active_canary_environment() -> dict[str, str]:
    return {
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "2500",
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


def test_preflight_active_canary_requires_matching_immutable_image_selector():
    environment = _active_canary_environment()
    failures: list[str] = []
    preflight._check_recon_provider_rollout(environment, failures)
    assert failures == []

    for image in ("", "aegis-kali:recon", "ghcr.io/aegisscan/kali-recon:latest"):
        broken = dict(environment)
        broken["AEGIS_KALI_RECON_IMAGE"] = image
        failures = []
        preflight._check_recon_provider_rollout(broken, failures)
        assert any("AEGIS_KALI_RECON_IMAGE" in item and "immutable" in item for item in failures), failures

    broken = dict(environment)
    broken["AEGIS_KALI_RECON_IMAGE"] = "ghcr.io/aegisscan/kali-recon@" + OTHER_DIGEST
    failures = []
    preflight._check_recon_provider_rollout(broken, failures)
    assert any("must match" in item for item in failures), failures


def test_preflight_legacy_and_zero_bps_rollback_do_not_require_provider_image():
    for environment in (
        {"AEGIS_RECON_PROVIDER": "legacy", "AEGIS_KALI_RECON_CANARY_BPS": "0"},
        {"AEGIS_RECON_PROVIDER": "canary", "AEGIS_KALI_RECON_CANARY_BPS": "0"},
    ):
        failures: list[str] = []
        preflight._check_recon_provider_rollout(environment, failures)
        assert failures == []


def test_resolved_policy_binds_active_canary_image_to_expected_digest():
    scanner_env = {
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "2500",
        "AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST": IMAGE_DIGEST,
    }
    services = {"kali_recon": {"image": IMMUTABLE_IMAGE}}
    failures: list[str] = []
    policy._validate_recon_image_binding(services, scanner_env, failures)
    assert failures == []

    failures = []
    policy._validate_recon_image_binding({}, scanner_env, failures)
    assert any("requires the kali_recon production service" in item for item in failures)

    failures = []
    policy._validate_recon_image_binding({"kali_recon": {"image": "aegis-kali:recon"}}, scanner_env, failures)
    assert any("immutable" in item for item in failures)

    mismatched = dict(scanner_env)
    mismatched["AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST"] = OTHER_DIGEST
    failures = []
    policy._validate_recon_image_binding(services, mismatched, failures)
    assert any("does not match" in item for item in failures)


def test_resolved_policy_preserves_legacy_and_zero_bps_rollback_without_kali_service():
    for scanner_env in (
        {"AEGIS_RECON_PROVIDER": "legacy", "AEGIS_KALI_RECON_CANARY_BPS": "0"},
        {"AEGIS_RECON_PROVIDER": "canary", "AEGIS_KALI_RECON_CANARY_BPS": "0"},
    ):
        failures: list[str] = []
        policy._validate_recon_image_binding({}, scanner_env, failures)
        assert failures == []


def test_rollback_environment_forces_pre_m4_compatible_legacy_mode():
    environment = {
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "2500",
        "COMPOSE_PROFILES": "monitoring,kali-recon",
        "UNRELATED_VALUE": "preserved",
    }
    rollback = deploy._rollback_execution_environment(environment)
    assert rollback["AEGIS_RECON_PROVIDER"] == "legacy"
    assert rollback["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
    assert rollback["COMPOSE_PROFILES"] == "monitoring"
    assert rollback["UNRELATED_VALUE"] == "preserved"


def test_active_canary_execution_plane_acceptance_requires_provider_and_attestation(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("placeholder=true\n", encoding="utf-8")
    environment = _active_canary_environment()
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
    assert "_preflight_runtime_attestation" in command
    assert "_trusted_expected_provenance" in command

    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"scanner_worker"})
    with pytest.raises(deploy.DeployError, match="kali_recon"):
        deploy._execution_plane_acceptance(env_file, environment, attempts=1)


def test_zero_bps_execution_plane_acceptance_does_not_require_kali_provider(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("placeholder=true\n", encoding="utf-8")
    environment = {
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
    }
    calls: list[list[str]] = []
    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"scanner_worker"})
    monkeypatch.setattr(
        deploy,
        "_run",
        lambda argv, **kwargs: calls.append(list(argv)) or SimpleNamespace(stdout="", returncode=0),
    )
    monkeypatch.setattr(deploy.time, "sleep", lambda *_: None)

    deploy._execution_plane_acceptance(env_file, environment, attempts=1)
    command = " ".join(calls[-1])
    assert "recon_provider_decision" in command
    assert "canary-rollback-zero" in command


def test_automatic_rollback_passes_only_safe_environment_to_runtime_acceptance(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text("placeholder=true\n", encoding="utf-8")
    environment = {
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "2500",
        "COMPOSE_PROFILES": "monitoring,kali-recon",
    }
    observed: dict[str, dict[str, str]] = {}

    monkeypatch.setattr(deploy, "_migration_changes", lambda *_: [])
    monkeypatch.setattr(deploy, "_checkout", lambda *_: None)
    monkeypatch.setattr(deploy, "_accept", lambda *_: None)
    monkeypatch.setattr(
        deploy,
        "_deploy_stack",
        lambda _env_file, env: observed.setdefault("deploy", dict(env)),
    )
    monkeypatch.setattr(
        deploy,
        "_execution_plane_acceptance",
        lambda _env_file, env: observed.setdefault("acceptance", dict(env)),
    )

    deploy._rollback_application(
        previous_sha="a" * 40,
        failed_release_sha="b" * 40,
        env_file=env_file,
        deployment_env=environment,
        origin="https://security.example.com",
    )

    for key in ("deploy", "acceptance"):
        assert observed[key]["AEGIS_RECON_PROVIDER"] == "legacy"
        assert observed[key]["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
        assert observed[key]["COMPOSE_PROFILES"] == "monitoring"
