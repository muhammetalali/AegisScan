import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_operational_acceptance.py"
SPEC = importlib.util.spec_from_file_location("production_operational_acceptance", PATH)
assert SPEC and SPEC.loader
ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ops)


def _secret(path: Path, content: str = "secret") -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def _env(tmp_path: Path) -> dict[str, str]:
    creds = _secret(tmp_path / "s3.json", '{}')
    key = _secret(tmp_path / "backup.key", "x" * 32)
    return {
        "ALERT_WEBHOOK_URL": "https://alerts.internal/aegis",
        "AEGIS_BACKUP_S3_ENDPOINT": "https://backup.internal",
        "AEGIS_BACKUP_S3_BUCKET": "aegis-production",
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE": str(creds),
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE": str(key),
    }


def test_compose_environment_preserves_governed_kali_and_adds_only_requested_profile(monkeypatch):
    monkeypatch.setattr(ops.os, "environ", {})
    env = {
        "AEGIS_RECON_PROVIDER": "default-kali",
        "COMPOSE_PROFILES": "existing-profile",
    }
    resolved = ops._compose_environment(env, extra_profiles={"ci-only"})
    assert set(resolved["COMPOSE_PROFILES"].split(",")) == {
        "ci-only",
        "existing-profile",
        "kali-recon",
    }


def test_operational_material_requires_https_and_private_backup_secrets(tmp_path: Path):
    env = _env(tmp_path)
    ops._validate_operational_material(env)

    bad = dict(env, ALERT_WEBHOOK_URL="http://alerts.internal/aegis")
    with pytest.raises(ops.OperationalAcceptanceError, match="HTTPS"):
        ops._validate_operational_material(bad)

    bad = dict(env, AEGIS_BACKUP_S3_ENDPOINT="http://backup.internal")
    with pytest.raises(ops.OperationalAcceptanceError, match="HTTPS"):
        ops._validate_operational_material(bad)

    Path(env["AEGIS_BACKUP_S3_CREDENTIALS_FILE"]).chmod(0o640)
    with pytest.raises(ops.OperationalAcceptanceError, match="0600"):
        ops._validate_operational_material(env)


def test_cleanup_is_repeatable_and_preserves_production_scope(monkeypatch, tmp_path):
    release = "a" * 40
    env = {"AUTHORIZED_SCAN_TARGETS": "security.internal", "SCANNER_EGRESS_PRIVATE_TARGETS": "10.20.30.40"}
    monkeypatch.setattr(ops, "_load_env", lambda _: dict(env))
    monkeypatch.setattr(ops, "_current_sha", lambda: release)
    commands = []
    monkeypatch.setattr(ops, "_run", lambda argv, **kw: commands.append((argv, kw)))
    monkeypatch.setattr(ops, "_wait_required_services", lambda *a, **kw: sorted(ops.REQUIRED_RUNNING_SERVICES))
    monkeypatch.setattr(ops, "_running_services", lambda *a, **kw: ops.REQUIRED_RUNNING_SERVICES)
    monkeypatch.setattr(ops, "_container_environment", lambda _: dict(env))
    for _ in range(2):
        result = ops.cleanup_e2e_scope(env_file=tmp_path / "production.env", release_sha=release)
        assert result["scan_target_stopped"] is True
        assert result["authorization_scope_restored"] is True
    restores = [(argv, kw) for argv, kw in commands if "--remove-orphans" in argv]
    assert len(restores) == 2
    assert all(kw["env"]["AUTHORIZED_SCAN_TARGETS"] == env["AUTHORIZED_SCAN_TARGETS"] for _, kw in restores)
    assert all("ci-only" not in kw["env"].get("COMPOSE_PROFILES", "") for _, kw in restores)

    commands.clear()
    monkeypatch.setattr(ops, "_current_sha", lambda: "b" * 40)
    with pytest.raises(ops.OperationalAcceptanceError, match="cleanup release SHA"):
        ops.cleanup_e2e_scope(env_file=tmp_path / "production.env", release_sha=release)
    assert not commands


def test_alertmanager_and_backup_probes_require_real_success(monkeypatch, tmp_path: Path):
    env_file = tmp_path / "production.env"
    env_file.write_text("X=1\n")

    calls = []
    def fake_run(argv, **kwargs):
        calls.append(argv)
        if "alertmanager" in argv:
            return SimpleNamespace(stdout="ready\n")
        if "backup" in argv:
            return SimpleNamespace(stdout=json.dumps({"status": "healthy", "backup_id": "bk-1", "age_seconds": 12}) + "\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(ops, "_run", fake_run)
    assert ops._wait_alertmanager(env_file, timeout_seconds=30, poll_seconds=1) == {"status": "ready"}
    backup = ops._wait_backup(env_file, timeout_seconds=60, poll_seconds=1)
    assert backup == {"status": "healthy", "backup_id": "bk-1", "age_seconds": 12}
    assert any("/-/ready" in " ".join(call) for call in calls)
    assert any(any("remote_backup_service.py" in item for item in call) for call in calls)


def test_accept_binds_release_and_emits_sanitized_operational_evidence(monkeypatch, tmp_path: Path):
    env_file = _secret(tmp_path / "production.env", "PLACEHOLDER=1\n")
    release = "a" * 40
    monkeypatch.setattr(ops, "_load_env", lambda path: _env(tmp_path))
    monkeypatch.setattr(ops, "_validate_operational_material", lambda env: None)
    monkeypatch.setattr(ops, "_current_sha", lambda: release)
    monkeypatch.setattr(ops, "_run", lambda *args, **kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(ops, "_wait_required_services", lambda *args, **kwargs: sorted(ops.REQUIRED_RUNNING_SERVICES))
    monkeypatch.setattr(ops, "_wait_alertmanager", lambda *args, **kwargs: {"status": "ready"})
    monkeypatch.setattr(
        ops,
        "_wait_backup",
        lambda *args, **kwargs: {"status": "healthy", "backup_id": "bk-real", "age_seconds": 7},
    )
    fixture = {
        "schema": "aegisscan.production-e2e-fixture.v1",
        "release_sha": release,
        "actor_id": "actor-1",
        "actor_email": "actor@example.invalid",
        "actor_password": "secret-actor-password",
        "approver_id": "approver-1",
        "approver_email": "approver@example.invalid",
        "approver_password": "secret-approver-password",
        "target": "172.31.0.9",
    }
    monkeypatch.setattr(
        ops,
        "_activate_e2e_scope",
        lambda *args, **kwargs: ("172.31.0.9", {"AUTHORIZED_SCAN_TARGETS": "security.example,172.31.0.9"}, sorted(ops.REQUIRED_RUNNING_SERVICES | {"scan_target"})),
    )
    monkeypatch.setattr(ops, "_provision_e2e_fixture", lambda *args, **kwargs: fixture)
    monkeypatch.setattr(
        ops,
        "_persist_e2e_fixture_for_deploy_user",
        lambda value: "/home/aegisdeploy/.aegis-e2e/e2e-fixture-" + "a" * 32 + ".json",
    )

    result = ops.accept(env_file=env_file, release_sha=release, poll_seconds=1)
    assert result["status"] == "success"
    assert result["release_sha"] == release
    assert result["alertmanager"] == {"status": "ready"}
    assert result["backup"]["backup_id"] == "bk-real"
    assert result["e2e_fixture_provisioned"] is True
    assert result["e2e_fixture_path"].endswith(".json")
    assert "scan_target" not in result["required_services"]
    assert result["e2e_scope"]["authorization_transient"] is True
    encoded = json.dumps(result)
    assert "alerts.internal" not in encoded
    assert "backup.internal" not in encoded
    assert "secret-actor-password" not in encoded
    assert "secret-approver-password" not in encoded

    monkeypatch.setattr(ops, "_current_sha", lambda: "b" * 40)
    with pytest.raises(ops.OperationalAcceptanceError, match="checkout"):
        ops.accept(env_file=env_file, release_sha=release, poll_seconds=1)


def test_e2e_fixture_bootstrap_uses_scoped_roles_and_never_prints_passwords(monkeypatch, tmp_path: Path):
    env_file = tmp_path / "production.env"
    env_file.write_text("X=1\n", encoding="utf-8")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["input_text"] = kwargs.get("input_text", "")
        return SimpleNamespace(stdout='{"actor_id":"a-1","approver_id":"b-1"}\n')

    monkeypatch.setattr(ops, "_run", fake_run)
    fixture = ops._provision_e2e_fixture(
        env_file,
        "c" * 40,
        "172.31.0.9",
        environment={"PATH": "/usr/bin"},
    )

    assert fixture["schema"] == "aegisscan.production-e2e-fixture.v1"
    assert fixture["target"] == "172.31.0.9"
    assert len(fixture["actor_password"]) >= 24
    assert len(fixture["approver_password"]) >= 24
    script = captured["input_text"]
    assert "role=UserRole.SECURITY_MANAGER" in script
    assert "role=UserRole.VIEWER" in script
    assert "stale_release_e2e_identity_deactivated" in script
    assert fixture["actor_password"] in script
    assert fixture["actor_password"] not in captured.get("stdout", "")
