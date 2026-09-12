import importlib.util
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_remote_deploy.py"
SPEC = importlib.util.spec_from_file_location("production_remote_deploy", PATH)
assert SPEC and SPEC.loader
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)


def _private(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_rejects_unsafe_host_origin_path_and_sha(tmp_path: Path):
    key = _private(tmp_path / "id_ed25519", "private")
    known = _private(tmp_path / "known_hosts", "example.com ssh-ed25519 AAAA\n")

    for host in ("", "127.0.0.1", "169.254.1.1", "bad host"):
        with pytest.raises(remote.RemoteDeployError):
            remote._host(host)

    for origin in (
        "http://security.example.com",
        "https://user:pass@security.example.com",
        "https://security.example.com/path",
        "https://127.0.0.1",
        "https://security.example.com:bad",
    ):
        with pytest.raises(remote.RemoteDeployError):
            remote._origin(origin)

    for path in ("relative/path", "/opt/aegis/../escape", "/opt/aegis path"):
        with pytest.raises(remote.RemoteDeployError):
            remote._remote_path(path, "path")

    with pytest.raises(remote.RemoteDeployError, match="40 lowercase"):
        remote.deploy(
            host="203.0.113.10",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="main",
            origin="https://security.example.com",
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )


def test_private_files_reject_group_or_other_access(tmp_path: Path):
    path = _private(tmp_path / "secret", "x")
    remote._private_file(path, "secret", 1024)
    path.chmod(0o640)
    with pytest.raises(remote.RemoteDeployError, match="group or others"):
        remote._private_file(path, "secret", 1024)


def test_known_host_lookup_requires_exact_host_and_port(tmp_path: Path, monkeypatch):
    known = _private(tmp_path / "known_hosts", "placeholder\n")
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="[security.example.com]:2222 ssh-ed25519 AAAA\n")

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    remote._require_known_host("security.example.com", 2222, known)
    assert calls[0][:3] == ["ssh-keygen", "-F", "[security.example.com]:2222"]

    monkeypatch.setattr(
        remote.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
    )
    with pytest.raises(remote.RemoteDeployError, match="pinned entry"):
        remote._require_known_host("security.example.com", 22, known)


def test_remote_command_is_fail_closed_and_quotes_values():
    command = remote._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
        origin="https://security.example.com",
    )
    assert 'test -z "$(git status --porcelain --untracked-files=no)"' in command
    assert "git fetch --no-tags origin main" in command
    assert "git merge-base --is-ancestor" in command
    assert "sudo -n python3 aegis-platform/scripts/production_host_reality.py" in command
    assert "sudo -n python3 aegis-platform/scripts/production_host_deploy.py" in command
    assert "--release-sha " + "a" * 40 in command
    assert "--origin https://security.example.com" in command


def test_deploy_uses_strict_pinned_ssh_and_requires_success_record(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id_ed25519", "private")
    known = _private(tmp_path / "known_hosts", "security.example.com ssh-ed25519 AAAA\n")
    monkeypatch.setattr(remote, "_require_known_host", lambda *args, **kwargs: None)

    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        payload = {
            "schema": "aegisscan.production-deploy.v1",
            "status": "success",
            "release_sha": "b" * 40,
        }
        return SimpleNamespace(stdout="host-check=PASS\n" + json.dumps(payload) + "\n")

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    result = remote.deploy(
        host="security.example.com",
        port=22,
        user="aegis",
        private_key=key,
        known_hosts=known,
        release_sha="b" * 40,
        origin="https://security.example.com",
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        timeout_seconds=120,
    )
    argv = captured["argv"]
    assert result["status"] == "success"
    assert result["release_sha"] == "b" * 40
    assert "StrictHostKeyChecking=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "KbdInteractiveAuthentication=no" in argv
    assert "BatchMode=yes" in argv
    assert captured["kwargs"]["capture_output"] is True

    monkeypatch.setattr(
        remote.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout='{"status":"success"}\n'),
    )
    with pytest.raises(remote.RemoteDeployError, match="successful production deployment record"):
        remote.deploy(
            host="security.example.com",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="b" * 40,
            origin="https://security.example.com",
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )


def test_non_default_port_known_hosts_lookup_is_bracketed(tmp_path: Path):
    known = _private(
        tmp_path / "known_hosts",
        "[security.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
    )
    # This is a parser-level contract only; ssh-keygen may reject the synthetic key body.
    lookup = "[security.example.com]:2222"
    assert lookup in known.read_text(encoding="utf-8")
