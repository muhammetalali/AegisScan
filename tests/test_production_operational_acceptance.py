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

    result = ops.accept(env_file=env_file, release_sha=release, poll_seconds=1)
    assert result["status"] == "success"
    assert result["release_sha"] == release
    assert result["alertmanager"] == {"status": "ready"}
    assert result["backup"]["backup_id"] == "bk-real"
    encoded = json.dumps(result)
    assert "alerts.internal" not in encoded
    assert "backup.internal" not in encoded

    monkeypatch.setattr(ops, "_current_sha", lambda: "b" * 40)
    with pytest.raises(ops.OperationalAcceptanceError, match="checkout"):
        ops.accept(env_file=env_file, release_sha=release, poll_seconds=1)
