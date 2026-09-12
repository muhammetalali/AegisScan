import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "aegis-platform/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
PATH = SCRIPTS / "production_resilience_backup.py"
SPEC = importlib.util.spec_from_file_location("production_resilience_backup", PATH)
assert SPEC and SPEC.loader
resilience = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resilience)


def _private(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_remote_backup_command_requires_exact_release_and_running_postgres():
    command = resilience._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
    )
    assert 'test "$(git rev-parse HEAD)" = ' + "a" * 40 in command
    assert "git merge-base --is-ancestor" in command
    assert "ps --status running --services | grep -qx postgres" in command
    assert "remote_backup_service.py once" in command
    assert "docker-compose.backup.yml" in command


def test_trigger_requires_versioned_durable_backup_record(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "security.example.com ssh-ed25519 AAAA\n")
    monkeypatch.setattr(resilience, "_require_known_host", lambda *args, **kwargs: None)

    payload = {
        "schema": "aegisscan.remote-backup.v1",
        "status": "success",
        "backup_id": "backup-1",
        "manifest_key": "aegisscan/postgres/backup-1/manifest.json",
        "manifest_version_id": "manifest-v1",
        "object_version_id": "object-v1",
        "source_sha256": "a" * 64,
    }

    captured = {}
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(stdout="noise\n" + json.dumps(payload) + "\n")

    monkeypatch.setattr(resilience.subprocess, "run", fake_run)
    result = resilience.trigger(
        host="security.example.com",
        port=22,
        user="aegis",
        private_key=key,
        known_hosts=known,
        release_sha="b" * 40,
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        timeout_seconds=120,
    )
    assert result["status"] == "success"
    assert result["backup"]["manifest_version_id"] == "manifest-v1"
    assert "StrictHostKeyChecking=yes" in captured["argv"]
    assert "PasswordAuthentication=no" in captured["argv"]

    monkeypatch.setattr(
        resilience.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps({
                "status": "success",
                "backup_id": "backup-2",
                "manifest_key": "manifest.json",
            }) + "\n"
        ),
    )
    with pytest.raises(resilience.ResilienceError, match="durable versioned backup"):
        resilience.trigger(
            host="security.example.com",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="b" * 40,
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )


def test_trigger_rejects_invalid_release_before_ssh(tmp_path: Path):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "security.example.com ssh-ed25519 AAAA\n")
    with pytest.raises(resilience.ResilienceError, match="40 lowercase"):
        resilience.trigger(
            host="security.example.com",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="main",
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )
