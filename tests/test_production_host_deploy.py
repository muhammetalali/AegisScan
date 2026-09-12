import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_host_deploy.py"
SPEC = importlib.util.spec_from_file_location("production_host_deploy", PATH)
assert SPEC and SPEC.loader
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)


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


def test_backup_skips_only_when_postgres_is_not_running(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    monkeypatch.setattr(deploy, "_running_services", lambda *_: set())
    result = deploy._backup_before_upgrade(env_file, {})
    assert result == {
        "performed": False,
        "reason": "first-deploy-or-postgres-not-running",
    }


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
            deployment_env={},
            origin="https://security.example.com",
        )


def test_automatic_rollback_redeploys_previous_release_without_migrations(tmp_path: Path, monkeypatch):
    env_file = _env_file(tmp_path)
    events = []
    monkeypatch.setattr(deploy, "_migration_changes", lambda *_: [])
    monkeypatch.setattr(deploy, "_checkout", lambda sha: events.append(("checkout", sha)))
    monkeypatch.setattr(deploy, "_deploy_stack", lambda *args, **kwargs: events.append(("deploy", None)))
    monkeypatch.setattr(deploy, "_accept", lambda origin: events.append(("accept", origin)))

    deploy._rollback_application(
        previous_sha="a" * 40,
        failed_release_sha="b" * 40,
        env_file=env_file,
        deployment_env={},
        origin="https://security.example.com",
    )
    assert events == [
        ("checkout", "a" * 40),
        ("deploy", None),
        ("accept", "https://security.example.com"),
    ]
