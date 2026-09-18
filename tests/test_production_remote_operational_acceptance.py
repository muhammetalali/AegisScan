import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_remote_operational_acceptance.py"
SPEC = importlib.util.spec_from_file_location("production_remote_operational_acceptance", PATH)
assert SPEC and SPEC.loader
remote_ops = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote_ops)


def _private(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_remote_command_binds_release_to_installed_privileged_acceptance_gate():
    command = remote_ops._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
    )
    assert command.startswith("sudo -n /usr/local/sbin/aegisscan-production-gate accept ")
    assert "--release-sha " + "a" * 40 in command
    assert "sudo -n python3" not in command
    assert "git rev-parse HEAD" not in command

    with pytest.raises(remote_ops.RemoteOperationalAcceptanceError, match="repository path"):
        remote_ops._remote_command(
            repo_path="/tmp/aegis",
            env_path="/etc/aegisscan/production.env",
            release_sha="a" * 40,
        )


def test_remote_acceptance_uses_private_dns_and_strict_pinned_ssh(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "deploy.internal ssh-ed25519 AAAA\n")
    release = "b" * 40

    monkeypatch.setattr(remote_ops.remote, "_host", lambda host: host)
    monkeypatch.setattr(remote_ops.remote, "_resolved_enterprise_addresses", lambda *args: ["10.20.30.10"])
    monkeypatch.setattr(remote_ops.remote, "_require_known_host", lambda *args: None)

    captured = {}
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        payload = {
            "schema": "aegisscan.production-operational-acceptance.v1",
            "status": "success",
            "release_sha": release,
            "alertmanager": {"status": "ready"},
            "backup": {"status": "healthy", "backup_id": "bk-1", "age_seconds": 2},
        }
        return SimpleNamespace(stdout=json.dumps(payload) + "\n")

    monkeypatch.setattr(remote_ops.subprocess, "run", fake_run)
    result = remote_ops.accept_remote(
        host="deploy.internal",
        port=22,
        user="aegis",
        private_key=key,
        known_hosts=known,
        release_sha=release,
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        timeout_seconds=120,
    )
    assert result["status"] == "success"
    assert result["host_resolved_addresses"] == ["10.20.30.10"]
    assert result["operational_acceptance"]["backup"]["backup_id"] == "bk-1"
    argv = captured["argv"]
    assert "StrictHostKeyChecking=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "KbdInteractiveAuthentication=no" in argv
    assert "BatchMode=yes" in argv


def test_remote_acceptance_rejects_missing_success_or_release_mismatch(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "deploy.internal ssh-ed25519 AAAA\n")
    monkeypatch.setattr(remote_ops.remote, "_host", lambda host: host)
    monkeypatch.setattr(remote_ops.remote, "_resolved_enterprise_addresses", lambda *args: ["10.20.30.10"])
    monkeypatch.setattr(remote_ops.remote, "_require_known_host", lambda *args: None)

    monkeypatch.setattr(
        remote_ops.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout='{"status":"success"}\n'),
    )
    with pytest.raises(remote_ops.RemoteOperationalAcceptanceError, match="successful operational"):
        remote_ops.accept_remote(
            host="deploy.internal", port=22, user="aegis", private_key=key, known_hosts=known,
            release_sha="c" * 40, repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env", timeout_seconds=120,
        )

    payload = {
        "schema": "aegisscan.production-operational-acceptance.v1",
        "status": "success",
        "release_sha": "d" * 40,
    }
    monkeypatch.setattr(
        remote_ops.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(payload) + "\n"),
    )
    with pytest.raises(remote_ops.RemoteOperationalAcceptanceError, match="release SHA mismatch"):
        remote_ops.accept_remote(
            host="deploy.internal", port=22, user="aegis", private_key=key, known_hosts=known,
            release_sha="c" * 40, repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env", timeout_seconds=120,
        )
