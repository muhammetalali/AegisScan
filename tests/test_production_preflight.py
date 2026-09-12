import os
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

PATH = Path(__file__).parents[1] / "aegis-platform/scripts/production_preflight.py"
SPEC = spec_from_file_location("production_preflight", PATH)
assert SPEC and SPEC.loader
preflight = module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def _private(path: Path, content: bytes) -> str:
    path.write_bytes(content)
    path.chmod(0o600)
    return str(path)


def valid_environment(tmp_path: Path) -> dict[str, str]:
    credentials = _private(
        tmp_path / "s3-credentials.json",
        b'{"access_key_id":"proof","secret_access_key":"proof-secret"}',
    )
    encryption_key = _private(
        tmp_path / "backup.key",
        b"0123456789abcdef0123456789abcdef",
    )
    return {
        "DEBUG": "False",
        "SECRET_KEY": "django-" + "a" * 40,
        "JWT_SECRET_KEY": "jwt-" + "b" * 40,
        "POSTGRES_PASSWORD": "postgres-" + "c" * 40,
        "DATABASE_URL": "postgresql://aegis:secret@postgres:5432/aegisdb",
        "REDIS_URL": "redis://redis:6379/0",
        "CELERY_BROKER_URL": "redis://redis:6379/0",
        "CELERY_RESULT_BACKEND": "redis://redis:6379/1",
        "ALLOWED_HOSTS": "security.example.com",
        "CORS_ALLOWED_ORIGINS": "https://security.example.com",
        "CSRF_TRUSTED_ORIGINS": "https://security.example.com",
        "AUTHORIZED_SCAN_TARGETS": "authorized.example.com,203.0.113.10",
        "ALERT_WEBHOOK_URL": "https://alerts.example.com/aegis",
        "AEGIS_REMOTE_BACKUP_ENABLED": "true",
        "AEGIS_BACKUP_S3_ENDPOINT": "https://backups.example.com",
        "AEGIS_BACKUP_S3_REGION": "us-east-1",
        "AEGIS_BACKUP_S3_BUCKET": "aegisscan-production-backups",
        "AEGIS_BACKUP_S3_PREFIX": "aegisscan/postgres",
        "AEGIS_BACKUP_S3_ADDRESSING_STYLE": "path",
        "AEGIS_BACKUP_REQUIRE_VERSIONING": "true",
        "AEGIS_BACKUP_INTERVAL_SECONDS": "86400",
        "AEGIS_BACKUP_RUNTIME_UID": str(os.getuid()),
        "AEGIS_BACKUP_RUNTIME_GID": str(os.getgid()),
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE": credentials,
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE": encryption_key,
    }


def test_accepts_explicit_non_default_production_configuration(tmp_path: Path):
    assert preflight.validate(valid_environment(tmp_path), tmp_path, check_tls=False) == []


def test_rejects_default_secrets_insecure_origins_dangerous_targets_and_alert_route(tmp_path: Path):
    environment = valid_environment(tmp_path)
    environment.update({
        "SECRET_KEY": "change-me",
        "JWT_SECRET_KEY": "change-me",
        "POSTGRES_PASSWORD": "password",
        "ALLOWED_HOSTS": "*",
        "CORS_ALLOWED_ORIGINS": "http://localhost",
        "CSRF_TRUSTED_ORIGINS": "http://localhost",
        "AUTHORIZED_SCAN_TARGETS": "127.0.0.1,169.254.169.254",
        "ALERT_WEBHOOK_URL": "http://127.0.0.1/hook",
    })
    failures = preflight.validate(environment, tmp_path, check_tls=False)
    assert len(failures) >= 8
    assert any("distinct" in failure for failure in failures)
    assert any("AUTHORIZED_SCAN_TARGETS" in failure for failure in failures)
    assert any("ALERT_WEBHOOK_URL" in failure for failure in failures)


def test_rejects_webhook_credentials_fragment_and_link_local_destination(tmp_path: Path):
    for webhook in (
        "https://user:pass@alerts.example.com/hook",
        "https://alerts.example.com/hook#secret",
        "https://169.254.169.254/hook",
        "",
    ):
        environment = valid_environment(tmp_path)
        environment["ALERT_WEBHOOK_URL"] = webhook
        failures = preflight.validate(environment, tmp_path, check_tls=False)
        assert any("ALERT_WEBHOOK_URL" in failure for failure in failures), webhook


def test_rejects_missing_tls_material(tmp_path: Path):
    failures = preflight.validate(valid_environment(tmp_path), tmp_path, check_tls=True)
    assert "TLS fullchain.pem and privkey.pem must both exist" in failures


def test_rejects_missing_or_insecure_remote_backup_configuration(tmp_path: Path):
    environment = valid_environment(tmp_path)
    key = Path(environment["AEGIS_BACKUP_ENCRYPTION_KEY_FILE"])
    key.chmod(0o644)
    environment.update({
        "AEGIS_BACKUP_S3_ENDPOINT": "http://127.0.0.1:9000",
        "AEGIS_BACKUP_S3_BUCKET": "INVALID_BUCKET",
        "AEGIS_BACKUP_S3_PREFIX": "../escape",
        "AEGIS_BACKUP_REQUIRE_VERSIONING": "false",
        "AEGIS_BACKUP_INTERVAL_SECONDS": "30",
    })
    failures = preflight.validate(environment, tmp_path, check_tls=False)
    assert any("AEGIS_BACKUP_S3_ENDPOINT" in failure for failure in failures)
    assert any("AEGIS_BACKUP_S3_BUCKET" in failure for failure in failures)
    assert any("AEGIS_BACKUP_S3_PREFIX" in failure for failure in failures)
    assert any("AEGIS_BACKUP_REQUIRE_VERSIONING" in failure for failure in failures)
    assert any("AEGIS_BACKUP_INTERVAL_SECONDS" in failure for failure in failures)
    assert any("AEGIS_BACKUP_ENCRYPTION_KEY_FILE" in failure for failure in failures)


def test_rejects_disabled_remote_backup(tmp_path: Path):
    environment = valid_environment(tmp_path)
    environment["AEGIS_REMOTE_BACKUP_ENABLED"] = "false"
    failures = preflight.validate(environment, tmp_path, check_tls=False)
    assert "AEGIS_REMOTE_BACKUP_ENABLED must be explicitly true" in failures
