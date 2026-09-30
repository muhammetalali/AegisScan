import importlib.util
import json
import os
import subprocess
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_host_deploy.py"
SPEC = importlib.util.spec_from_file_location("production_host_deploy", PATH)
assert SPEC and SPEC.loader
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)

TRUST_PATH = ROOT / "aegis-platform/scripts/production_execution_trust_bootstrap.py"
TRUST_SPEC = importlib.util.spec_from_file_location("production_execution_trust_bootstrap", TRUST_PATH)
assert TRUST_SPEC and TRUST_SPEC.loader
trust = importlib.util.module_from_spec(TRUST_SPEC)
TRUST_SPEC.loader.exec_module(trust)


@pytest.fixture(autouse=True)
def _isolate_alert_receiver_token_path(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(deploy, "ALERT_RECEIVER_TOKEN_PATH", tmp_path / "alert-receiver-token")
    monkeypatch.setattr(deploy.os, "chown", lambda *_args: None)


def _env_file(tmp_path: Path) -> Path:
    path = tmp_path / "production.env"
    path.write_text(
        "\n".join(
            [
                "DEBUG=False",
                "SECRET_KEY=django-" + "a" * 40,
                "JWT_SECRET_KEY=jwt-" + "b" * 40,
                "POSTGRES_PASSWORD=postgres-" + "c" * 40,
                "DATABASE_URL=postgresql://aegis:secret@postgres:5432/aegisdb",
                "REDIS_URL=redis://redis:6379/0",
                "CELERY_BROKER_URL=redis://redis:6379/0",
                "CELERY_RESULT_BACKEND=redis://redis:6379/1",
                "ALLOWED_HOSTS=security.example.com",
                "CORS_ALLOWED_ORIGINS=https://security.example.com",
                "CSRF_TRUSTED_ORIGINS=https://security.example.com",
                "AUTHORIZED_SCAN_TARGETS=authorized.example.com,203.0.113.10",
                "ALERT_WEBHOOK_URL=https://alerts.example.com/aegis",
                "AEGIS_REMOTE_BACKUP_ENABLED=true",
                "AEGIS_BACKUP_S3_ENDPOINT=https://backups.example.com",
                "AEGIS_BACKUP_S3_BUCKET=aegisscan-production-backups",
                "AEGIS_BACKUP_S3_PREFIX=aegisscan/postgres",
                "AEGIS_BACKUP_REQUIRE_VERSIONING=true",
                "AEGIS_BACKUP_INTERVAL_SECONDS=86400",
                "AEGIS_BACKUP_S3_CREDENTIALS_FILE=/run/secrets/s3.json",
                "AEGIS_BACKUP_ENCRYPTION_KEY_FILE=/run/secrets/backup.key",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def test_env_file_must_be_private(tmp_path: Path):
    path = _env_file(tmp_path)
    path.chmod(0o644)
    with pytest.raises(deploy.DeployError, match="mode 0600"):
        deploy._load_env_file(path)


def test_env_file_parses_only_explicit_assignments(tmp_path: Path):
    path = _env_file(tmp_path)
    values = deploy._load_env_file(path)
    assert values["DEBUG"] == "False"
    assert values["ALLOWED_HOSTS"] == "security.example.com"

    bad = tmp_path / "bad.env"
    bad.write_text("GOOD=value\nnot valid\n", encoding="utf-8")
    bad.chmod(0o600)
    with pytest.raises(deploy.DeployError, match="line 2"):
        deploy._load_env_file(bad)


def test_release_sha_and_public_origin_fail_closed(monkeypatch):
    with pytest.raises(deploy.DeployError, match="40 lowercase"):
        deploy._ensure_release("main")
    assert deploy._validate_origin("https://security.example.com") == "https://security.example.com"
    with pytest.raises(deploy.DeployError, match="explicit HTTPS origin"):
        deploy._validate_origin("http://security.example.com")
    with pytest.raises(deploy.DeployError):
        deploy._validate_origin("https://user:pass@security.example.com/path")


def test_migration_change_detection_filters_only_migrations(monkeypatch):
    monkeypatch.setattr(
        deploy,
        "_git",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="aegis-platform/backend/django_project/users/migrations/0002_x.py\nREADME.md\n"
        ),
    )
    assert deploy._migration_changes("a" * 40, "b" * 40) == [
        "aegis-platform/backend/django_project/users/migrations/0002_x.py"
    ]


def test_privileged_storage_reclaim_restores_target_without_volume_prune(monkeypatch):
    free = {"value": 50 * deploy.GIB}
    commands = []

    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: free["value"])
    monkeypatch.setattr(deploy, "_docker_df", lambda: "docker-df")

    def fake_run(argv, **kwargs):
        commands.append(list(argv))
        if argv[:3] == ["docker", "builder", "prune"]:
            free["value"] += 10 * deploy.GIB
        elif argv[:3] == ["docker", "container", "prune"]:
            free["value"] += 4 * deploy.GIB
        elif argv[:3] == ["docker", "image", "prune"]:
            free["value"] += 5 * deploy.GIB
        return SimpleNamespace(stdout="ok\n")

    monkeypatch.setattr(deploy, "_run", fake_run)
    result = deploy._host_storage_reclaim()

    assert result["status"] == "success"
    assert result["after_free_bytes"] >= 68 * deploy.GIB
    assert result["volume_prune_performed"] is False
    assert all("volume" not in token for argv in commands for token in argv)


def test_privileged_storage_reclaim_fails_closed_below_minimum(monkeypatch):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 50 * deploy.GIB)
    monkeypatch.setattr(deploy, "_docker_df", lambda: "docker-df")
    monkeypatch.setattr(deploy, "_run", lambda *args, **kwargs: SimpleNamespace(stdout="ok\n"))

    with pytest.raises(deploy.DeployError, match="still below the production minimum"):
        deploy._host_storage_reclaim()


def test_backup_skips_only_when_postgres_is_not_running(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(deploy, "_running_services", lambda *_: set())
    result = deploy._backup_before_upgrade(env_file, {})
    assert result == {
        "performed": False,
        "reason": "first-deploy-or-postgres-not-running",
    }


def test_backup_invocation_uses_backup_entrypoint_command_only(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"postgres"})
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "status": "success",
                    "backup_id": "backup-entrypoint-proof",
                    "manifest_key": "m.json",
                    "manifest_version_id": "v1",
                }
            )
            + "\n"
        )

    monkeypatch.setattr(deploy, "_run", fake_run)

    result = deploy._backup_before_upgrade(env_file, {})

    assert result["performed"] is True
    assert calls
    backup_run = calls[0]
    assert backup_run[-2:] == ["backup", "once"]
    assert "/app/scripts/remote_backup_service.py" not in backup_run
    assert "python" not in backup_run[-4:]


def test_backup_requires_durable_success_payload(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(deploy, "_running_services", lambda *_: {"postgres"})
    monkeypatch.setattr(
        deploy,
        "_run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps(
                {
                    "status": "success",
                    "backup_id": "backup-123",
                    "manifest_key": "m.json",
                    "manifest_version_id": "v1",
                }
            )
            + "\n"
        ),
    )
    result = deploy._backup_before_upgrade(env_file, {})
    assert result["performed"] is True
    assert result["backup_id"] == "backup-123"


def test_automatic_rollback_is_blocked_when_schema_changed(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(
        deploy,
        "_migration_changes",
        lambda *_: ["backend/app/migrations/0002_change.py"],
    )
    with pytest.raises(deploy.DeployError, match="automatic rollback blocked"):
        deploy._rollback_application(
            previous_sha="a" * 40,
            failed_release_sha="b" * 40,
            env_file=env_file,
            previous_env_snapshot=deploy._snapshot_private_env(env_file),
            origin="https://security.example.com",
        )


def test_automatic_rollback_redeploys_previous_release_without_migrations(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    events = []
    monkeypatch.setattr(deploy, "_migration_changes", lambda *_: [])
    monkeypatch.setattr(deploy, "_checkout", lambda sha: events.append(("checkout", sha)))
    monkeypatch.setattr(deploy, "_build_stack", lambda *_: events.append(("build", None)))
    monkeypatch.setattr(deploy, "_assert_storage_floor", lambda _stage: 60 * deploy.GIB)
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *args, **kwargs: events.append(("deploy", None)))
    monkeypatch.setattr(
        deploy,
        "_execution_plane_acceptance",
        lambda *args, **kwargs: events.append(("execution-plane", None)),
    )
    monkeypatch.setattr(deploy, "_accept", lambda origin: events.append(("accept", origin)))

    snapshot = deploy._snapshot_private_env(env_file)
    original = env_file.read_bytes()
    env_file.write_text("DEBUG=False\nAEGIS_RECON_PROVIDER=default-kali\n", encoding="utf-8")
    env_file.chmod(0o600)

    deploy._rollback_application(
        previous_sha="a" * 40,
        failed_release_sha="b" * 40,
        env_file=env_file,
        previous_env_snapshot=snapshot,
        origin="https://security.example.com",
    )
    assert env_file.read_bytes() == original
    assert events == [
        ("checkout", "a" * 40),
        ("build", None),
        ("deploy", None),
        ("execution-plane", None),
        ("accept", "https://security.example.com"),
    ]




@pytest.mark.parametrize("same_release", [False, True])
def test_failed_preflight_restores_exact_previous_env_and_checkout(tmp_path: Path, monkeypatch, same_release):
    env_file = _env_file(tmp_path)
    original = env_file.read_bytes()
    previous_sha = "a" * 40
    release_sha = previous_sha if same_release else "b" * 40
    checkouts = []

    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_restore_tracked_checkout", lambda _sha: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: previous_sha)
    monkeypatch.setattr(
        deploy,
        "_host_storage_reclaim",
        lambda: {"schema": "aegisscan.production-host-storage-reclaim.v1", "status": "success"},
    )
    monkeypatch.setattr(
        deploy,
        "_backup_before_upgrade",
        lambda *_args: {"performed": False, "reason": "first-deploy"},
    )
    monkeypatch.setattr(deploy, "_checkout", lambda sha: checkouts.append(sha))

    def prepare(path, _sha):
        path.write_text(
            "DEBUG=False\nAEGIS_RECON_PROVIDER=default-kali\nAEGIS_RECON_LEGACY_DISABLED=true\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return deploy._load_env_file(path)

    monkeypatch.setattr(deploy, "_prepare_execution_trust", prepare)
    monkeypatch.setattr(
        deploy,
        "_preflight",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("preflight failed")),
    )

    with pytest.raises(RuntimeError, match="preflight failed"):
        deploy.deploy(release_sha, env_file, "https://security.example.com")

    assert checkouts == ([release_sha] if same_release else [release_sha, previous_sha])
    assert env_file.read_bytes() == original
    assert env_file.stat().st_mode & 0o777 == 0o600


def test_failed_backup_leaves_checkout_and_private_environment_untouched(tmp_path, monkeypatch):
    env_file = _env_file(tmp_path)
    original = env_file.read_bytes()
    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: "a" * 40)
    monkeypatch.setattr(
        deploy,
        "_host_storage_reclaim",
        lambda: {"schema": "aegisscan.production-host-storage-reclaim.v1", "status": "success"},
    )
    def fail_backup(*args):
        raise deploy.DeployError("backup failed")
    monkeypatch.setattr(deploy, "_backup_before_upgrade", fail_backup)
    monkeypatch.setattr(deploy, "_checkout", lambda _sha: pytest.fail("checkout before backup"))
    with pytest.raises(deploy.DeployError, match="backup failed"):
        deploy.deploy("b" * 40, env_file, "https://security.internal")
    assert env_file.read_bytes() == original
    assert not deploy.ALERT_RECEIVER_TOKEN_PATH.exists()


def test_schema_blocked_rollback_keeps_new_release_env_bound(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    snapshot = deploy._snapshot_private_env(env_file)
    env_file.write_text(
        "DEBUG=False\nAEGIS_RECON_PROVIDER=default-kali\nAEGIS_RECON_LEGACY_DISABLED=true\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    new_env = env_file.read_bytes()

    monkeypatch.setattr(
        deploy,
        "_migration_changes",
        lambda *_: ["backend/app/migrations/0002_change.py"],
    )

    with pytest.raises(deploy.DeployError, match="automatic rollback blocked"):
        deploy._rollback_application(
            previous_sha="a" * 40,
            failed_release_sha="b" * 40,
            env_file=env_file,
            previous_env_snapshot=snapshot,
            origin="https://security.example.com",
        )

    assert env_file.read_bytes() == new_env



def test_execution_profile_environment_pins_enterprise_ca_host_bundle():
    resolved = deploy._execution_profile_environment({})
    assert resolved["AEGIS_ENTERPRISE_CA_HOST_BUNDLE"] == "/etc/aegisscan/enterprise-ca.pem"

def test_execution_profile_environment_activates_governed_kali_for_default_and_active_canary():
    base = {"AEGIS_RECON_PROVIDER": "legacy", "AEGIS_KALI_RECON_CANARY_BPS": "0"}
    legacy = deploy._execution_profile_environment(base)
    assert "COMPOSE_PROFILES" not in legacy

    default_kali = deploy._execution_profile_environment({
        "AEGIS_RECON_PROVIDER": "default-kali",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
        "COMPOSE_PROFILES": "monitoring",
    })
    assert set(default_kali["COMPOSE_PROFILES"].split(",")) == {"monitoring", "kali-recon"}

    canary = deploy._execution_profile_environment({
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "250",
        "COMPOSE_PROFILES": "monitoring",
    })
    assert set(canary["COMPOSE_PROFILES"].split(",")) == {"monitoring", "kali-recon"}

    rollback = deploy._execution_profile_environment({
        "AEGIS_RECON_PROVIDER": "canary",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
        "COMPOSE_PROFILES": "monitoring,kali-recon",
    })
    assert rollback["COMPOSE_PROFILES"] == "monitoring"


def test_execution_profile_environment_keeps_explicit_kali_runtime_available_for_nonproduction_proof():
    resolved = deploy._execution_profile_environment({
        "AEGIS_RECON_PROVIDER": "kali",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
    })
    assert resolved["COMPOSE_PROFILES"] == "kali-recon"


def test_rollback_preserves_retired_legacy_protection():
    rollback = deploy._rollback_execution_environment({
        "AEGIS_RECON_PROVIDER": "default-kali",
        "AEGIS_RECON_LEGACY_DISABLED": "true",
        "AEGIS_KALI_RECON_CANARY_BPS": "0",
    })
    assert rollback["AEGIS_RECON_PROVIDER"] == "default-kali"
    assert rollback["AEGIS_RECON_LEGACY_DISABLED"] == "true"
    assert rollback["AEGIS_KALI_RECON_CANARY_BPS"] == "0"
    assert "kali-recon" in rollback["COMPOSE_PROFILES"].split(",")


def test_rollback_only_defaults_missing_pre_m4_fields():
    rollback = deploy._rollback_execution_environment({})
    assert rollback["AEGIS_RECON_PROVIDER"] == "legacy"
    assert rollback["AEGIS_RECON_LEGACY_DISABLED"] == "false"
    assert "COMPOSE_PROFILES" not in rollback


def test_deploy_bootstraps_exact_runtime_trust_before_full_preflight(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    release_sha = "b" * 40
    events = []

    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: events.append("clean"))
    monkeypatch.setattr(deploy, "_ensure_release", lambda sha: events.append(("ensure", sha)))
    monkeypatch.setattr(deploy, "_current_sha", lambda: release_sha)
    monkeypatch.setattr(
        deploy,
        "_host_storage_reclaim",
        lambda: events.append("storage") or {
            "schema": "aegisscan.production-host-storage-reclaim.v1",
            "status": "success",
        },
    )
    monkeypatch.setattr(
        deploy,
        "_backup_before_upgrade",
        lambda *_args: events.append("backup") or {"performed": False, "reason": "first-deploy"},
    )
    monkeypatch.setattr(deploy, "_checkout", lambda sha: events.append(("checkout", sha)))

    def prepare(path, sha):
        events.append(("trust", sha))
        values = deploy._load_env_file(path)
        values["AEGIS_RECON_PROVIDER"] = "default-kali"
        values["AEGIS_RECON_LEGACY_DISABLED"] = "true"
        return values

    monkeypatch.setattr(deploy, "_prepare_execution_trust", prepare)
    monkeypatch.setattr(deploy, "_preflight", lambda *_args: events.append("preflight"))
    monkeypatch.setattr(deploy, "_build_stack", lambda *_args: events.append("build"))
    monkeypatch.setattr(deploy, "_assert_storage_floor", lambda _stage: 60 * deploy.GIB)
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *_args: events.append("deploy"))
    monkeypatch.setattr(deploy, "_execution_plane_acceptance", lambda *_args: events.append("execution"))
    monkeypatch.setattr(deploy, "_accept", lambda *_args: events.append("accept"))
    monkeypatch.setattr(
        deploy,
        "_alert_delivery_acceptance",
        lambda *_args: events.append("alerts") or {
            "status": "success",
            "authenticated": True,
            "transport": "https",
            "receiver": "internal",
            "baseline_events": 1.0,
            "current_events": 2.0,
        },
    )
    monkeypatch.setattr(
        deploy,
        "_retire_legacy_alert_delivery_network",
        lambda: events.append("legacy-network-cleanup") or {"status": "removed", "removed": True},
    )

    result = deploy.deploy(release_sha, env_file, "https://security.example.com")

    assert result["status"] == "success"
    assert result["alert_delivery"]["authenticated"] is True
    assert result["legacy_alert_network_cleanup"]["removed"] is True
    assert events.index("backup") < events.index("storage")
    assert events.index("storage") < events.index(("checkout", release_sha))
    assert events.index(("checkout", release_sha)) < events.index(("trust", release_sha))
    assert events.index(("trust", release_sha)) < events.index("preflight")
    assert events.index("preflight") < events.index("build") < events.index("deploy")
    assert events.index("deploy") < events.index("execution") < events.index("accept") < events.index("alerts") < events.index("legacy-network-cleanup")


def test_alert_delivery_acceptance_rejects_unrelated_counter_increment(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    counts = iter([1.0, 2.0])

    def metric(_env, _deployment, name):
        if name == "aegis_alert_receiver_events_total":
            return next(counts)
        return 0.0

    monkeypatch.setattr(deploy, "_alert_receiver_metric", metric)
    monkeypatch.setattr(deploy, "_alert_receiver_delivery_evidence", lambda *_args: None)
    monkeypatch.setattr(deploy, "_run", lambda *_args, **_kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(deploy.time, "sleep", lambda _seconds: None)
    with pytest.raises(deploy.DeployError, match="did not reach the receiver"):
        deploy._alert_delivery_acceptance(env_file, {}, "a" * 40, attempts=1)


def test_alert_delivery_acceptance_binds_success_to_exact_audit_evidence(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    event_counts = iter([7.0, 8.0])
    auth_counts = iter([0.0, 0.0])
    rejected_counts = iter([0.0, 0.0])

    def metric(_env, _deployment, name):
        if name == "aegis_alert_receiver_events_total":
            return next(event_counts)
        if name == "aegis_alert_receiver_unauthorized_total":
            return next(auth_counts)
        if name == "aegis_alert_receiver_rejected_total":
            return next(rejected_counts)
        raise AssertionError(name)

    proof_sha = "f" * 64
    monkeypatch.setattr(deploy, "_alert_receiver_metric", metric)
    monkeypatch.setattr(
        deploy,
        "_alert_receiver_delivery_evidence",
        lambda *_args: {
            "alertnames": ["AegisProductionAlertDeliveryAcceptance"],
            "release_shas": ["b" * 40],
            "payload_sha256": proof_sha,
        },
    )
    monkeypatch.setattr(deploy, "_run", lambda *_args, **_kwargs: SimpleNamespace(stdout=""))
    monkeypatch.setattr(deploy.time, "sleep", lambda _seconds: None)
    result = deploy._alert_delivery_acceptance(env_file, {}, "b" * 40, attempts=1)
    assert result["audit_payload_sha256"] == proof_sha
    assert result["proof_release_sha"] == "b" * 40
    assert result["proof_alertname"] == "AegisProductionAlertDeliveryAcceptance"


def test_runtime_trust_bootstrap_contract_is_exercised_by_launch_gate():
    values = {}
    trust._ensure_tokens(values)
    assert set(trust.TOKEN_NAMES).issubset(values)
    assert all(len(values[name]) == 64 for name in trust.TOKEN_NAMES)

    image_id = "sha256:" + "1" * 64
    manifest = {
        "runner_version": "0.1.0",
        "build_commit": "2" * 40,
        "base_image_digest": "sha256:" + "3" * 64,
        "tool_manifest_digest": "sha256:" + "4" * 64,
    }
    bound = trust._trust_values("RECON", image_id, manifest, b"runtime\n")
    assert bound["AEGIS_KALI_RECON_IMAGE"] == image_id
    assert bound["AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST"] == image_id
    assert bound["AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT"] == "2" * 40


def test_scanner_state_reports_only_allowlisted_runtime_fields(tmp_path, monkeypatch):
    commands = []

    def run(argv, **kwargs):
        commands.append(argv)
        if argv[:2] == ['docker', 'inspect']:
            return SimpleNamespace(stdout='status=restarting exit=1 oom=false restarting=true restarts=7\n')
        return SimpleNamespace(stdout='a' * 64 + '\n')

    monkeypatch.setattr(deploy, '_run', run)
    result = deploy._scanner_worker_state(tmp_path / 'production.env', {})
    assert result == 'status=restarting exit=1 oom=false restarting=true restarts=7'
    assert commands[0][-4:] == ['ps', '--all', '--quiet', 'scanner_worker']
    assert commands[1][2] == '--format'
    assert '.Config' not in commands[1][3]
    assert '.State.Error' not in commands[1][3]


@pytest.mark.parametrize('output', ['', 'not-a-container secret-value'])
def test_scanner_state_rejects_missing_or_invalid_container_ids(tmp_path, monkeypatch, output):
    commands = []
    def run(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(stdout=output)
    monkeypatch.setattr(deploy, '_run', run)
    result = deploy._scanner_worker_state(tmp_path / 'production.env', {})
    assert len(commands) == 1
    assert 'secret-value' not in result


def test_acceptance_preserves_original_failure_when_diagnostics_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(deploy, '_running_services', lambda *_: set())
    monkeypatch.setattr(deploy.time, 'sleep', lambda *_: None)
    def run(*args, **kwargs):
        raise deploy.subprocess.CalledProcessError(1, ['docker'], stderr='secret-value')
    monkeypatch.setattr(deploy, '_run', run)
    with pytest.raises(deploy.DeployError) as failure:
        deploy._execution_plane_acceptance(tmp_path / 'production.env', {}, attempts=1)
    assert 'scanner_worker is not running' in str(failure.value)
    assert 'state unavailable' in str(failure.value)
    assert 'secret-value' not in str(failure.value)


def test_interrupted_same_release_restores_tracked_checkout_and_private_env(tmp_path, monkeypatch):
    env_file = _env_file(tmp_path)
    release = "a" * 40
    events = []

    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: release)
    monkeypatch.setattr(deploy, "_backup_before_upgrade", lambda *_: {"performed": False})
    monkeypatch.setattr(
        deploy,
        "_host_storage_reclaim",
        lambda: {"schema": "aegisscan.production-host-storage-reclaim.v1", "status": "success"},
    )
    monkeypatch.setattr(deploy, "_checkout", lambda sha: events.append(("checkout", sha)))
    monkeypatch.setattr(
        deploy,
        "_prepare_execution_trust",
        lambda path, sha: deploy._load_env_file(path),
    )
    monkeypatch.setattr(deploy, "_preflight", lambda *_: None)
    monkeypatch.setattr(deploy, "_build_stack", lambda *_: {})
    monkeypatch.setattr(deploy, "_assert_storage_floor", lambda _stage: 60 * deploy.GIB)
    monkeypatch.setattr(
        deploy,
        "_deploy_stack",
        lambda *_: (_ for _ in ()).throw(deploy.DeploymentInterrupted("cancelled")),
    )
    monkeypatch.setattr(
        deploy,
        "_restore_tracked_checkout",
        lambda sha: events.append(("restore-checkout", sha)),
    )
    monkeypatch.setattr(
        deploy,
        "_restore_private_env",
        lambda path, snapshot: events.append(("restore-env", path)),
    )

    with pytest.raises(deploy.DeploymentInterrupted, match="cancelled"):
        deploy.deploy(release, env_file, "https://security.example.com")

    assert ("restore-checkout", release) in events
    assert ("restore-env", env_file) in events


def test_deployment_signal_handler_raises_controlled_interrupt():
    with pytest.raises(deploy.DeploymentInterrupted, match="SIGTERM"):
        deploy._deployment_signal_handler(deploy.signal.SIGTERM, None)


def test_storage_floor_fails_before_service_mutation(monkeypatch):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 59 * deploy.GIB)
    with pytest.raises(deploy.DeployError, match="60 GiB safety floor"):
        deploy._assert_storage_floor("execution-trust-bootstrap")


def test_storage_floor_accepts_exact_minimum(monkeypatch):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 60 * deploy.GIB)
    assert deploy._assert_storage_floor("application-image-build") == 60 * deploy.GIB


def test_production_28_capacity_recovers_before_start_without_pruning_images_or_volumes(tmp_path, monkeypatch):
    free = {"value": 87996936192}
    calls = []
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: free["value"])
    monkeypatch.setattr(deploy, "_docker_df", lambda: "storage-summary")

    def run(argv, **kwargs):
        calls.append(list(argv))
        if "build" in argv:
            free["value"] = 63833497600  # Exact observed Production #28 failure.
        elif argv[:3] == ["docker", "builder", "prune"] and "--filter" not in argv:
            free["value"] += 2 * deploy.GIB
        elif "up" in argv:
            assert free["value"] >= deploy.PRODUCTION_MINIMUM_FREE_BYTES
        return SimpleNamespace(stdout="cache reclaimed\n")

    validation_calls = []
    monkeypatch.setattr(deploy, "_validate_nginx_config", lambda env, values: validation_calls.append((env, values)))
    monkeypatch.setattr(deploy, "_run", run)
    env_file = _env_file(tmp_path)
    result = deploy._build_stack(env_file, {})
    deploy._deploy_stack(env_file, {})

    assert result["before_free_bytes"] == 63833497600
    assert result["after_free_bytes"] == 63833497600 + 2 * deploy.GIB
    assert result["remaining_deficit_bytes"] == 0
    assert result["status"] == "success"
    assert len(calls) == 5
    assert calls[1] == ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"]
    assert calls[2] == ["docker", "builder", "prune", "--all", "--force"]
    assert validation_calls == [(env_file, {})]
    assert "up" in calls[3] and "--no-build" in calls[3]
    assert calls[4][-3:] == ["--no-deps", "--force-recreate", "nginx"]
    assert all(argv[:3] not in (["docker", "image", "prune"], ["docker", "container", "prune"],
                              ["docker", "volume", "prune"], ["docker", "system", "prune"])
               for argv in calls)




def test_validate_nginx_config_uses_isolated_docker_run(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    nginx_config = tmp_path / "nginx.conf"
    nginx_config.write_text("events {}\nhttp {}\n", encoding="utf-8")
    tls_dir = tmp_path / "ssl"
    tls_dir.mkdir()
    calls = []

    monkeypatch.setattr(deploy, "_compose", lambda _env, *args: ["docker", "compose", *args])

    def run(argv, **kwargs):
        calls.append(list(argv))
        if "config" in argv:
            return SimpleNamespace(
                stdout=json.dumps(
                    {
                        "services": {
                            "nginx": {
                                "image": "nginx:1.30.5-alpine",
                                "volumes": [
                                    {
                                        "type": "bind",
                                        "source": str(nginx_config),
                                        "target": "/etc/nginx/nginx.conf",
                                        "read_only": True,
                                    },
                                    {
                                        "type": "bind",
                                        "source": str(tls_dir),
                                        "target": "/etc/nginx/ssl",
                                        "read_only": True,
                                    },
                                    {
                                        "type": "volume",
                                        "source": "aegis-platform_static_data",
                                        "target": "/usr/share/nginx/html/static",
                                    },
                                ],
                            }
                        }
                    }
                )
            )
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(deploy, "_run", run)
    deploy._validate_nginx_config(env_file, {})

    assert len(calls) == 2
    assert calls[0][:3] == ["docker", "compose", "config"] or calls[0][2:4] == ["config", "--format"]
    isolated = calls[1]
    assert isolated[:3] == ["docker", "run", "--rm"]
    assert isolated[isolated.index("--network") + 1] == "none"
    assert isolated[isolated.index("--entrypoint") + 1] == "nginx"
    assert "nginx:1.30.5-alpine" in isolated
    assert isolated[-2:] == ["nginx:1.30.5-alpine", "-t"]
    assert not any(argv[:2] == ["docker", "compose"] and "run" in argv for argv in calls)
    assert any(str(nginx_config) in arg for arg in isolated)
    assert any(str(tls_dir) in arg for arg in isolated)



def test_unrecoverable_build_capacity_does_not_start_services(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 63833497600)
    monkeypatch.setattr(deploy, "_docker_df", lambda: "storage-summary")
    calls = []
    monkeypatch.setattr(deploy, "_run", lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(stdout=""))
    with pytest.raises(deploy.DeployError, match="60 GiB safety floor"):
        deploy._build_stack(_env_file(tmp_path), {})
    assert not any("up" in argv for argv in calls)
    evidence = json.loads(capsys.readouterr().out)
    assert evidence["status"] == "insufficient-capacity"
    assert evidence["remaining_deficit_bytes"] == 591011840
    assert evidence["volume_prune_performed"] is False


def test_healthy_build_preserves_resumable_cache(monkeypatch, capsys):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 61 * deploy.GIB)
    monkeypatch.setattr(deploy, "_run", lambda *_args, **_kwargs: pytest.fail("healthy build must preserve cache"))
    result = deploy._post_build_storage("execution-trust-bootstrap")
    assert result["stages"] == []
    assert result["reclaimed_bytes"] == 0
    assert json.loads(capsys.readouterr().out)["status"] == "success"


def test_trust_build_also_recovers_capacity_before_preflight(tmp_path, monkeypatch):
    free = {"value": 59 * deploy.GIB}
    calls = []
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: free["value"])
    monkeypatch.setattr(deploy, "_docker_df", lambda: "storage-summary")

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["docker", "builder", "prune"]:
            free["value"] = 65 * deploy.GIB
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(deploy, "_run", run)
    env_file = _env_file(tmp_path)
    values = deploy._prepare_execution_trust(env_file, "b" * 40)
    assert values == deploy._load_env_file(env_file)
    assert len(calls) == 2  # Trust helper, then aged cache; full cache is unnecessary.
    assert free["value"] >= deploy.PRODUCTION_MINIMUM_FREE_BYTES


@pytest.mark.parametrize("same_release", [False, True])
def test_build_failure_restores_checkout_and_env_without_redeploying_running_services(tmp_path, monkeypatch, same_release):
    env_file = _env_file(tmp_path)
    original = env_file.read_bytes()
    previous_sha = "a" * 40
    release_sha = previous_sha if same_release else "b" * 40
    checkouts = []
    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_restore_tracked_checkout", lambda _sha: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: previous_sha)
    monkeypatch.setattr(deploy, "_backup_before_upgrade", lambda *_: {"performed": False})
    monkeypatch.setattr(deploy, "_host_storage_reclaim", lambda: {})
    monkeypatch.setattr(deploy, "_checkout", lambda sha: checkouts.append(sha))

    def prepare(path, _sha):
        path.write_text("DEBUG=False\nAEGIS_RECON_PROVIDER=default-kali\n", encoding="utf-8")
        return deploy._load_env_file(path)

    monkeypatch.setattr(deploy, "_prepare_execution_trust", prepare)
    monkeypatch.setattr(deploy, "_preflight", lambda *_: None)
    monkeypatch.setattr(deploy, "_build_stack", lambda *_: (_ for _ in ()).throw(deploy.DeployError("build capacity failed")))
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *_: pytest.fail("build failure must not change services"))
    monkeypatch.setattr(deploy, "_rollback_application", lambda **_: pytest.fail("untouched services need no rollback"))

    with pytest.raises(deploy.DeployError, match="build capacity failed"):
        deploy.deploy(release_sha, env_file, "https://security.example.com")
    assert env_file.read_bytes() == original
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert checkouts == ([release_sha] if same_release else [release_sha, previous_sha])


def test_rollback_failure_preserves_original_deployment_cause(tmp_path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_restore_tracked_checkout", lambda _sha: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: "a" * 40)
    monkeypatch.setattr(deploy, "_backup_before_upgrade", lambda *_: {"performed": False})
    monkeypatch.setattr(deploy, "_host_storage_reclaim", lambda: {})
    monkeypatch.setattr(deploy, "_checkout", lambda _sha: None)
    monkeypatch.setattr(deploy, "_prepare_execution_trust", lambda path, _sha: deploy._load_env_file(path))
    monkeypatch.setattr(deploy, "_preflight", lambda *_: None)
    monkeypatch.setattr(deploy, "_build_stack", lambda *_: {})
    monkeypatch.setattr(deploy, "_assert_storage_floor", lambda _stage: 60 * deploy.GIB)
    original_failure = deploy.DeployError("scanner service failed")
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *_: (_ for _ in ()).throw(original_failure))
    monkeypatch.setattr(deploy, "_rollback_application", lambda **_: (_ for _ in ()).throw(deploy.DeployError("rollback capacity failed")))
    with pytest.raises(deploy.DeployError) as exc:
        deploy.deploy("b" * 40, env_file, "https://security.example.com")
    assert "scanner service failed" in str(exc.value)
    assert "rollback capacity failed" in str(exc.value)
    assert exc.value.__cause__ is original_failure
    # A failed rollback may leave the new stack partially running. Retain the
    # private token rather than breaking its authenticated receiver mid-failure.
    assert deploy.ALERT_RECEIVER_TOKEN_PATH.is_file()


def test_capacity_loss_after_build_restores_state_before_any_service_change(tmp_path, monkeypatch):
    env_file = _env_file(tmp_path)
    original = env_file.read_bytes()
    checkouts = []
    monkeypatch.setattr(deploy, "_assert_clean_repo", lambda: None)
    monkeypatch.setattr(deploy, "_restore_tracked_checkout", lambda _sha: None)
    monkeypatch.setattr(deploy, "_ensure_release", lambda _sha: None)
    monkeypatch.setattr(deploy, "_current_sha", lambda: "a" * 40)
    monkeypatch.setattr(deploy, "_backup_before_upgrade", lambda *_: {"performed": False})
    monkeypatch.setattr(deploy, "_host_storage_reclaim", lambda: {})
    monkeypatch.setattr(deploy, "_checkout", lambda sha: checkouts.append(sha))
    monkeypatch.setattr(deploy, "_prepare_execution_trust", lambda path, _sha: deploy._load_env_file(path))
    monkeypatch.setattr(deploy, "_preflight", lambda *_: None)
    monkeypatch.setattr(deploy, "_build_stack", lambda *_: {"after_free_bytes": 60 * deploy.GIB})
    # Another writer consumes capacity between successful build and start.
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 59 * deploy.GIB)
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *_: pytest.fail("capacity loss must precede service mutation"))
    monkeypatch.setattr(deploy, "_rollback_application", lambda **_: pytest.fail("services were never changed"))
    with pytest.raises(deploy.DeployError, match="before-service-start"):
        deploy.deploy("b" * 40, env_file, "https://security.example.com")
    assert checkouts == ["b" * 40, "a" * 40]
    assert env_file.read_bytes() == original

def test_post_build_storage_reclaim_uses_build_cache_only(monkeypatch):
    free = {"value": 59 * deploy.GIB}
    commands = []
    monkeypatch.setattr(deploy, "_docker_df", lambda: "storage-summary")

    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: free["value"])

    def fake_run(argv, **kwargs):
        commands.append(list(argv))
        if argv == ["docker", "builder", "prune", "--all", "--force"]:
            free["value"] = 61 * deploy.GIB
        return SimpleNamespace(stdout="reclaimed\n")

    monkeypatch.setattr(deploy, "_run", fake_run)
    result = deploy._post_build_storage("application-image-build")

    assert result["mode"] == "floor-restored"
    assert result["before_free_bytes"] == 59 * deploy.GIB
    assert result["after_free_bytes"] == 61 * deploy.GIB
    assert result["image_prune_performed"] is False
    assert result["volume_prune_performed"] is False
    assert commands == [
        ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"],
        ["docker", "builder", "prune", "--all", "--force"],
    ]


def test_post_build_storage_reclaim_remains_fail_closed_when_cache_is_insufficient(monkeypatch):
    monkeypatch.setattr(deploy, "_free_bytes", lambda path=deploy.PLATFORM_DIR: 59 * deploy.GIB)
    monkeypatch.setattr(deploy, "_docker_df", lambda: "storage-summary")
    monkeypatch.setattr(deploy, "_run", lambda *args, **kwargs: SimpleNamespace(stdout="nothing to reclaim\n"))

    with pytest.raises(deploy.DeployError, match="60 GiB safety floor"):
        deploy._post_build_storage("application-image-build")


def test_deploy_stack_recovers_post_build_floor_before_service_mutation(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    events = []

    monkeypatch.setattr(
        deploy,
        "_compose",
        lambda _env, *args: ["docker", "compose", *args],
    )
    monkeypatch.setattr(
        deploy,
        "_run",
        lambda argv, **kwargs: events.append(tuple(argv)) or SimpleNamespace(stdout=""),
    )
    monkeypatch.setattr(
        deploy,
        "_post_build_storage",
        lambda _stage: events.append(("recover-post-build-storage",)) or {},
    )

    monkeypatch.setattr(deploy, "_assert_storage_floor", lambda _stage: 60 * deploy.GIB)
    monkeypatch.setattr(deploy, "_validate_nginx_config", lambda *_: events.append(("validate-nginx-config",)))
    deploy._build_stack(env_file, {})
    deploy._deploy_stack(env_file, {})

    assert events == [
        ("docker", "compose", "build", "--pull"),
        ("recover-post-build-storage",),
        ("validate-nginx-config",),
        ("docker", "compose", "up", "-d", "--no-build", "--remove-orphans"),
        ("docker", "compose", "up", "-d", "--no-build", "--no-deps", "--force-recreate", "nginx"),
    ]


def test_invalid_gateway_config_stops_build_boundary_before_service_start(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(deploy, "_compose", lambda _env, *args: ["docker", "compose", *args])
    monkeypatch.setattr(deploy, "_post_build_storage", lambda _stage: {"status": "success"})
    monkeypatch.setattr(
        deploy,
        "_run",
        lambda argv, **kwargs: calls.append(argv) or SimpleNamespace(stdout=""),
    )

    def reject_nginx_config(*_args):
        raise subprocess.CalledProcessError(1, ["docker", "run", "nginx", "-t"], stderr="invalid gateway configuration")

    monkeypatch.setattr(deploy, "_validate_nginx_config", reject_nginx_config)
    with pytest.raises(subprocess.CalledProcessError):
        deploy._build_stack(_env_file(tmp_path), {})
    assert calls == [["docker", "compose", "build", "--pull"]]



def test_reconcile_internal_alert_receiver_bootstraps_private_material(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "ALLOWED_HOSTS=security.example.com\nALERT_WEBHOOK_URL=\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    token = tmp_path / "secrets" / "alert-receiver-token"
    monkeypatch.setattr(deploy, "ALERT_RECEIVER_TOKEN_PATH", token)
    monkeypatch.setattr(deploy.os, "chown", lambda *_args: None)

    values = deploy._reconcile_internal_alert_receiver(
        env_file,
        "https://security.example.com",
    )

    assert values["AEGIS_PRODUCTION_DOMAIN"] == "security.example.com"
    assert values["ALERT_WEBHOOK_URL"] == "https://security.example.com:8443/_aegis/alerts"
    assert values["AEGIS_ALERT_RECEIVER_TOKEN_FILE"] == str(token)
    assert token.is_file()
    assert stat.S_IMODE(token.stat().st_mode) == 0o600
    assert len(token.read_bytes().strip()) >= 32


def test_reconcile_internal_alert_receiver_migrates_explicit_external_override(tmp_path: Path, monkeypatch):
    env_file = tmp_path / "production.env"
    env_file.write_text(
        "ALLOWED_HOSTS=security.example.com\nALERT_WEBHOOK_URL=https://alerts.example.com/aegis\n",
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    token = tmp_path / "secrets" / "alert-receiver-token"
    monkeypatch.setattr(deploy, "ALERT_RECEIVER_TOKEN_PATH", token)
    monkeypatch.setattr(deploy.os, "chown", lambda *_args: None)

    values = deploy._reconcile_internal_alert_receiver(
        env_file,
        "https://security.example.com",
    )

    assert values["ALERT_WEBHOOK_URL"] == "https://security.example.com:8443/_aegis/alerts"
    assert values["AEGIS_ALERT_RECEIVER_TOKEN_FILE"] == str(token)
    assert token.is_file()


def test_private_alert_delivery_network_uses_versioned_name():
    compose = (ROOT / "aegis-platform/docker-compose.monitoring.yml").read_text(encoding="utf-8")
    assert "alert_delivery_v2" in compose
    assert "  alert_delivery_v2:\n    internal: true" in compose
    assert "  alert_delivery:\n" not in compose


def test_legacy_alert_delivery_network_is_removed_only_after_it_is_empty(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["network", "ls"]:
            return SimpleNamespace(stdout="0123456789ab\n")
        if argv[1:3] == ["network", "inspect"]:
            return SimpleNamespace(stdout="{}")
        if argv[1:3] == ["network", "rm"]:
            return SimpleNamespace(stdout="0123456789ab")
        raise AssertionError(argv)

    monkeypatch.setattr(deploy, "_run", run)
    result = deploy._retire_legacy_alert_delivery_network()

    assert result == {"status": "removed", "removed": True, "active_endpoints": 0}
    assert calls[-1] == ["docker", "network", "rm", "0123456789ab"]


def test_legacy_alert_delivery_network_with_live_endpoints_is_preserved(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["network", "ls"]:
            return SimpleNamespace(stdout="0123456789ab\n")
        if argv[1:3] == ["network", "inspect"]:
            return SimpleNamespace(stdout='{"aegis-nginx": {"Name": "aegis-nginx"}}')
        raise AssertionError(argv)

    monkeypatch.setattr(deploy, "_run", run)
    with pytest.raises(deploy.DeployError, match="still has active endpoints after private network acceptance: 1"):
        deploy._retire_legacy_alert_delivery_network()

    assert not any(argv[1:3] == ["network", "rm"] for argv in calls)
