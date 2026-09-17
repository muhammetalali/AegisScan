import importlib.util
import json
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


def _private_dns(monkeypatch):
    def fake_getaddrinfo(host, port, **kwargs):
        mapping = {
            "deploy.internal": "10.20.30.10",
            "security.internal": "10.20.30.20",
        }
        return [(remote.socket.AF_INET, remote.socket.SOCK_STREAM, 6, "", (mapping[host], port))]

    monkeypatch.setattr(remote.socket, "getaddrinfo", fake_getaddrinfo)


def test_rejects_unsafe_or_nonprivate_host_origin_path_and_sha(tmp_path: Path):
    key = _private(tmp_path / "id_ed25519", "private")
    known = _private(tmp_path / "known_hosts", "deploy.internal ssh-ed25519 AAAA\n")

    for host in ("", "127.0.0.1", "169.254.1.1", "203.0.113.10", "bad host"):
        with pytest.raises(remote.RemoteDeployError):
            remote._host(host)

    for origin in (
        "http://security.internal",
        "https://user:pass@security.internal",
        "https://security.internal/path",
        "https://127.0.0.1",
        "https://203.0.113.10",
        "https://security.internal:bad",
    ):
        with pytest.raises(remote.RemoteDeployError):
            remote._origin(origin)

    for path in ("relative/path", "/opt/aegis/../escape", "/opt/aegis path"):
        with pytest.raises(remote.RemoteDeployError):
            remote._remote_path(path, "path")

    with pytest.raises(remote.RemoteDeployError, match="40 lowercase"):
        remote.deploy(
            host="10.20.30.10",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="main",
            origin="https://10.20.30.20",
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )


def test_private_dns_rejects_any_public_resolution(monkeypatch):
    monkeypatch.setattr(
        remote.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (remote.socket.AF_INET, remote.socket.SOCK_STREAM, 6, "", ("10.20.30.10", 443)),
            (remote.socket.AF_INET, remote.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ],
    )
    with pytest.raises(remote.RemoteDeployError, match="outside RFC1918/IPv6-ULA"):
        remote._resolved_enterprise_addresses("security.internal", 443, "production origin")


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
        return SimpleNamespace(returncode=0, stdout="[deploy.internal]:2222 ssh-ed25519 AAAA\n")

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    remote._require_known_host("deploy.internal", 2222, known)
    assert calls[0][:3] == ["ssh-keygen", "-F", "[deploy.internal]:2222"]

    monkeypatch.setattr(remote.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""))
    with pytest.raises(remote.RemoteDeployError, match="pinned entry"):
        remote._require_known_host("deploy.internal", 22, known)


def test_remote_command_is_fail_closed_and_quotes_values():
    command = remote._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
        origin="https://security.internal",
    )
    assert 'test -z "$(git status --porcelain --untracked-files=no)"' in command
    assert "git fetch --no-tags origin main" in command
    assert "git merge-base --is-ancestor" in command
    assert "sudo -n python3 aegis-platform/scripts/production_host_reality.py" in command
    assert "sudo -n python3 aegis-platform/scripts/production_host_deploy.py" in command
    assert "--release-sha " + "a" * 40 in command
    assert "--origin https://security.internal" in command


def test_deploy_uses_private_dns_strict_pinned_ssh_and_requires_success_record(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id_ed25519", "private")
    known = _private(tmp_path / "known_hosts", "deploy.internal ssh-ed25519 AAAA\n")
    _private_dns(monkeypatch)
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
        host="deploy.internal",
        port=22,
        user="aegis",
        private_key=key,
        known_hosts=known,
        release_sha="b" * 40,
        origin="https://security.internal",
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        timeout_seconds=120,
    )
    argv = captured["argv"]
    assert result["status"] == "success"
    assert result["deployment_mode"] == "internal"
    assert result["network_scope"] == "rfc1918-or-ipv6-ula"
    assert result["host_resolved_addresses"] == ["10.20.30.10"]
    assert result["origin_resolved_addresses"] == ["10.20.30.20"]
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
            host="deploy.internal",
            port=22,
            user="aegis",
            private_key=key,
            known_hosts=known,
            release_sha="b" * 40,
            origin="https://security.internal",
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/etc/aegisscan/production.env",
            timeout_seconds=120,
        )


def test_non_default_port_known_hosts_lookup_is_bracketed(tmp_path: Path):
    known = _private(
        tmp_path / "known_hosts",
        "[deploy.internal]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
    )
    assert "[deploy.internal]:2222" in known.read_text(encoding="utf-8")
