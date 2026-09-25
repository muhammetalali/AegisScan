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

    cleanup = remote_ops._remote_cleanup_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
    )
    assert cleanup.startswith("sudo -n /usr/local/sbin/aegisscan-production-gate cleanup-e2e-scope ")

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
    monkeypatch.setattr(remote_ops.remote, "_require_known_host", lambda *args, **kwargs: "10.20.30.10")

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
            "e2e_fixture_provisioned": True,
            "e2e_fixture_path": "/home/aegisdeploy/.aegis-e2e/e2e-fixture-" + "a" * 32 + ".json",
        }
        return SimpleNamespace(stdout=json.dumps(payload) + "\n")

    monkeypatch.setattr(remote_ops.subprocess, "run", fake_run)
    fixture_output = tmp_path / "e2e-fixture.json"
    transferred = {}
    def fake_transfer(**kwargs):
        transferred.update(kwargs)
        kwargs["local_path"].write_text('{"schema":"aegisscan.production-e2e-fixture.v1"}\n', encoding="utf-8")
        kwargs["local_path"].chmod(0o600)
    monkeypatch.setattr(remote_ops, "_transfer_private_fixture", fake_transfer)
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
        e2e_fixture_output=fixture_output,
    )
    assert result["status"] == "success"
    assert result["host_resolved_addresses"] == ["10.20.30.10"]
    assert result["operational_acceptance"]["backup"]["backup_id"] == "bk-1"
    assert result["e2e_fixture_transferred"] is True
    assert "e2e_fixture_path" not in result["operational_acceptance"]
    assert transferred["remote_path"].endswith(".json")
    assert transferred["local_path"] == fixture_output
    assert transferred["host_key_alias"] == "10.20.30.10"
    argv = captured["argv"]
    assert "StrictHostKeyChecking=yes" in argv
    assert "HostKeyAlias=10.20.30.10" in argv
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
            e2e_fixture_output=tmp_path / "fixture-a.json",
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
            e2e_fixture_output=tmp_path / "fixture-b.json",
        )


def test_remote_cleanup_restores_scope_over_strict_pinned_ssh(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id-cleanup", "private")
    known = _private(tmp_path / "known-cleanup", "deploy.internal ssh-ed25519 AAAA\n")
    release = "e" * 40

    monkeypatch.setattr(remote_ops.remote, "_host", lambda host: host)
    monkeypatch.setattr(remote_ops.remote, "_resolved_enterprise_addresses", lambda *args: ["10.20.30.10"])
    monkeypatch.setattr(remote_ops.remote, "_require_known_host", lambda *args: None)

    captured = {}
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        payload = {
            "schema": "aegisscan.production-e2e-scope-cleanup.v1",
            "status": "success",
            "release_sha": release,
            "scan_target_stopped": True,
            "authorization_scope_restored": True,
            "scanner_egress_scope_restored": True,
        }
        return SimpleNamespace(stdout=json.dumps(payload) + "\n")

    monkeypatch.setattr(remote_ops.subprocess, "run", fake_run)
    result = remote_ops.cleanup_remote(
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
    assert result["scope_cleanup"]["scan_target_stopped"] is True
    assert "cleanup-e2e-scope" in captured["argv"][-1]
    assert "StrictHostKeyChecking=yes" in captured["argv"]


def test_private_fixture_transfer_rejects_untrusted_remote_path(tmp_path: Path):
    key = _private(tmp_path / "id2", "private")
    known = _private(tmp_path / "known_hosts2", "deploy.internal ssh-ed25519 AAAA\n")
    with pytest.raises(remote_ops.RemoteOperationalAcceptanceError, match="path is invalid"):
        remote_ops._transfer_private_fixture(
            host="deploy.internal",
            port=22,
            user="aegisdeploy",
            private_key=key,
            known_hosts=known,
            remote_path="/tmp/attacker-controlled.json",
            local_path=tmp_path / "fixture.json",
        )
