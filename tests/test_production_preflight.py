from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

PATH = Path(__file__).parents[1] / "aegis-platform/scripts/production_preflight.py"
SPEC = spec_from_file_location("production_preflight", PATH)
assert SPEC and SPEC.loader
preflight = module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def valid_environment() -> dict[str, str]:
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
    }


def test_accepts_explicit_non_default_production_configuration(tmp_path: Path):
    assert preflight.validate(valid_environment(), tmp_path, check_tls=False) == []


def test_rejects_default_secrets_insecure_origins_and_dangerous_targets(tmp_path: Path):
    environment = valid_environment()
    environment.update({
        "SECRET_KEY": "change-me",
        "JWT_SECRET_KEY": "change-me",
        "POSTGRES_PASSWORD": "password",
        "ALLOWED_HOSTS": "*",
        "CORS_ALLOWED_ORIGINS": "http://localhost",
        "CSRF_TRUSTED_ORIGINS": "http://localhost",
        "AUTHORIZED_SCAN_TARGETS": "127.0.0.1,169.254.169.254",
    })
    failures = preflight.validate(environment, tmp_path, check_tls=False)
    assert len(failures) >= 7
    assert any("distinct" in failure for failure in failures)
    assert any("AUTHORIZED_SCAN_TARGETS" in failure for failure in failures)


def test_rejects_missing_tls_material(tmp_path: Path):
    failures = preflight.validate(valid_environment(), tmp_path, check_tls=True)
    assert "TLS fullchain.pem and privkey.pem must both exist" in failures
