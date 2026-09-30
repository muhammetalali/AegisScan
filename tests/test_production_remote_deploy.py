import importlib.util
import io
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


def test_known_host_lookup_accepts_only_existing_resolved_private_pin(tmp_path: Path, monkeypatch):
    known = _private(tmp_path / "known_hosts", "10.20.30.10 ssh-ed25519 AAAA\n")
    calls = []

    def fake_run(argv, **kwargs):
        lookup = argv[2]
        calls.append(lookup)
        if lookup == "10.20.30.10":
            return SimpleNamespace(returncode=0, stdout="10.20.30.10 ssh-ed25519 AAAA\n")
        return SimpleNamespace(returncode=1, stdout="")

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    alias = remote._require_known_host(
        "deploy.internal",
        22,
        known,
        resolved_addresses=["10.20.30.10"],
    )
    assert alias == "10.20.30.10"
    assert calls[:3] == ["deploy.internal", "[deploy.internal]:22", "10.20.30.10"]


def test_remote_command_is_fail_closed_and_uses_installed_privileged_gate():
    command = remote._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
        origin="https://security.internal",
    )
    assert command.startswith("sudo -n /usr/local/sbin/aegisscan-production-gate deploy ")
    assert "--release-sha " + "a" * 40 in command
    assert "--origin https://security.internal" in command
    assert "sudo -n python3" not in command
    assert "git fetch" not in command

    with pytest.raises(remote.RemoteDeployError, match="repository path"):
        remote._remote_command(
            repo_path="/tmp/aegis",
            env_path="/etc/aegisscan/production.env",
            release_sha="a" * 40,
            origin="https://security.internal",
        )
    with pytest.raises(remote.RemoteDeployError, match="environment path"):
        remote._remote_command(
            repo_path="/opt/aegisscan/AegisScan",
            env_path="/tmp/production.env",
            release_sha="a" * 40,
            origin="https://security.internal",
        )


def test_deploy_uses_private_dns_strict_pinned_ssh_and_requires_success_record(tmp_path: Path, monkeypatch, capsys):
    key = _private(tmp_path / "id_ed25519", "private")
    known = _private(tmp_path / "known_hosts", "deploy.internal ssh-ed25519 AAAA\n")
    _private_dns(monkeypatch)
    monkeypatch.setattr(remote, "_require_known_host", lambda *args, **kwargs: "10.20.30.10")

    captured = {}
    output = {
        "text": "host-check=PASS\n"
        + json.dumps(
            {
                "schema": "aegisscan.production-deploy.v1",
                "status": "success",
                "release_sha": "b" * 40,
            }
        )
        + "\n"
    }

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            self.stdout = io.StringIO(output["text"])
            self.returncode = 0
            self.killed = False

        def wait(self, timeout=None):
            captured["timeout"] = timeout
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -9

    monkeypatch.setattr(remote.subprocess, "Popen", FakePopen)
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
    assert "HostKeyAlias=10.20.30.10" in argv
    assert "PasswordAuthentication=no" in argv
    assert "KbdInteractiveAuthentication=no" in argv
    assert "BatchMode=yes" in argv
    assert captured["kwargs"]["stdout"] is remote.subprocess.PIPE
    assert captured["kwargs"]["stderr"] is remote.subprocess.STDOUT
    assert captured["kwargs"]["text"] is True
    assert captured["timeout"] == 120
    streamed = capsys.readouterr()
    assert streamed.out == ""
    assert "host-check=PASS" in streamed.err

    output["text"] = '{"status":"success"}\n'
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


def test_streaming_remote_deploy_kills_ssh_on_timeout(monkeypatch):
    class TimeoutPopen:
        def __init__(self, _argv, **_kwargs):
            self.stdout = io.StringIO("build-progress\n")
            self.killed = False

        def wait(self, timeout=None):
            if not self.killed:
                raise remote.subprocess.TimeoutExpired(["ssh"], timeout)
            return -9

        def kill(self):
            self.killed = True

    monkeypatch.setattr(remote.subprocess, "Popen", TimeoutPopen)
    with pytest.raises(remote.RemoteDeployError, match="timed out after 60 seconds"):
        remote._stream_remote_deploy(["ssh"], timeout_seconds=60)


def test_non_default_port_known_hosts_lookup_is_bracketed(tmp_path: Path):
    known = _private(
        tmp_path / "known_hosts",
        "[deploy.internal]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
    )
    assert "[deploy.internal]:2222" in known.read_text(encoding="utf-8")


def test_checkout_repair_uses_only_current_head_and_installed_gate(monkeypatch):
    current = "a" * 40
    prefix = ["ssh", "-o", "StrictHostKeyChecking=yes", "aegisdeploy@deploy.internal"]
    calls = []
    monkeypatch.setattr(
        remote.subprocess, "run",
        lambda argv, **kwargs: calls.append((argv, kwargs)) or SimpleNamespace(stdout=current + "\n"),
    )

    def stream(argv, **kwargs):
        calls.append((argv, kwargs))
        return {
            "schema": "aegisscan.production-privileged-gate.v1",
            "status": "success", "action": "repair-checkout", "release_sha": current,
        }

    monkeypatch.setattr(remote, "_stream_remote_deploy", stream)
    result = remote._repair_current_checkout(prefix, timeout_seconds=14400)
    assert result["release_sha"] == current
    assert calls[0][0][:-1] == calls[1][0][:-1] == prefix
    assert calls[0][0][-1].endswith("rev-parse HEAD")
    assert calls[1][0][-1] == (
        "sudo -n /usr/local/sbin/aegisscan-production-gate repair-checkout --release-sha " + current
    )
    assert calls[1][1]["timeout_seconds"] == 900
    assert calls[1][1]["payload_schema"] == "aegisscan.production-privileged-gate.v1"


@pytest.mark.parametrize("current", ["main", "a" * 40 + "\nextra", "a" * 40 + ";id"])
def test_checkout_repair_rejects_invalid_head_before_privileged_action(monkeypatch, current):
    monkeypatch.setattr(remote.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout=current))
    monkeypatch.setattr(remote, "_stream_remote_deploy", lambda *_args, **_kwargs: pytest.fail("invalid HEAD reached gate"))
    with pytest.raises(remote.RemoteDeployError, match="invalid current HEAD"):
        remote._repair_current_checkout(["ssh"], timeout_seconds=120)


@pytest.mark.parametrize("record", [
    None,
    {"status": "failed", "action": "repair-checkout", "release_sha": "a" * 40},
    {"status": "success", "action": "deploy", "release_sha": "a" * 40},
    {"status": "success", "action": "repair-checkout", "release_sha": "b" * 40},
])
def test_checkout_repair_requires_gate_proof_for_the_existing_head(monkeypatch, record):
    monkeypatch.setattr(remote.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(stdout="a" * 40))
    monkeypatch.setattr(remote, "_stream_remote_deploy", lambda *_args, **_kwargs: record)
    with pytest.raises(remote.RemoteDeployError, match="did not prove repair"):
        remote._repair_current_checkout(["ssh"], timeout_seconds=120)


def test_opted_in_repair_precedes_deployment_and_preserves_ssh_pins(tmp_path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "private pin")
    _private_dns(monkeypatch)
    monkeypatch.setattr(remote, "_require_known_host", lambda *_args, **_kwargs: "10.20.30.10")
    events = []

    def repair(argv, **kwargs):
        events.append(("repair", argv))
        return {"status": "success", "action": "repair-checkout", "release_sha": "a" * 40}

    def stream(argv, **kwargs):
        events.append(("deploy", argv))
        return {"schema": "aegisscan.production-deploy.v1", "status": "success", "release_sha": "b" * 40}

    monkeypatch.setattr(remote, "_repair_current_checkout", repair)
    monkeypatch.setattr(remote, "_stream_remote_deploy", stream)
    result = remote.deploy(
        host="deploy.internal", port=22, user="aegisdeploy", private_key=key, known_hosts=known,
        release_sha="b" * 40, origin="https://security.internal",
        repo_path=remote.PRODUCTION_REPO_PATH, env_path=remote.PRODUCTION_ENV_PATH,
        timeout_seconds=120, repair_current_checkout=True,
    )
    assert [event[0] for event in events] == ["repair", "deploy"]
    assert events[0][1] == events[1][1][:-1]
    assert "HostKeyAlias=10.20.30.10" in events[0][1]
    assert "StrictHostKeyChecking=yes" in events[0][1]
    assert result["checkout_repair"]["release_sha"] == "a" * 40


def test_failed_checkout_repair_prevents_deployment(tmp_path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "private pin")
    _private_dns(monkeypatch)
    monkeypatch.setattr(remote, "_require_known_host", lambda *_args, **_kwargs: "deploy.internal")
    monkeypatch.setattr(
        remote, "_repair_current_checkout",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(remote.RemoteDeployError("repair denied")),
    )
    monkeypatch.setattr(remote, "_stream_remote_deploy", lambda *_args, **_kwargs: pytest.fail("repair failure reached deploy"))
    with pytest.raises(remote.RemoteDeployError, match="repair denied"):
        remote.deploy(
            host="deploy.internal", port=22, user="aegisdeploy", private_key=key, known_hosts=known,
            release_sha="b" * 40, origin="https://security.internal",
            repo_path=remote.PRODUCTION_REPO_PATH, env_path=remote.PRODUCTION_ENV_PATH,
            timeout_seconds=120, repair_current_checkout=True,
        )


def test_json_output_is_atomically_written_as_machine_readable_payload(tmp_path):
    output = tmp_path / "nested" / "deploy.json"
    output.parent.mkdir()
    output.write_text("incomplete mixed logs", encoding="utf-8")
    payload = {"schema": "aegisscan.remote-production-deploy.v1", "status": "success"}

    remote._write_json_output(output, payload)

    assert json.loads(output.read_text(encoding="utf-8")) == payload
    assert list(output.parent.glob(".deploy.json.*.tmp")) == []
    assert output.stat().st_mode & 0o077 == 0


def test_main_writes_clean_deploy_result_when_output_json_is_requested(tmp_path, monkeypatch, capsys):
    output = tmp_path / "deploy.json"
    payload = {"schema": "aegisscan.remote-production-deploy.v1", "status": "success"}
    monkeypatch.setattr(remote, "deploy", lambda **_kwargs: payload)
    monkeypatch.setattr(remote.sys, "argv", [
        "production_remote_deploy.py",
        "--host", "deploy.internal",
        "--port", "22",
        "--user", "aegis",
        "--private-key", str(tmp_path / "id"),
        "--known-hosts", str(tmp_path / "known_hosts"),
        "--release-sha", "b" * 40,
        "--origin", "https://security.internal",
        "--output-json", str(output),
    ])

    assert remote.main() == 0

    assert json.loads(output.read_text(encoding="utf-8")) == payload
    printed = capsys.readouterr()
    assert json.loads(printed.out) == payload
    assert printed.err == ""
