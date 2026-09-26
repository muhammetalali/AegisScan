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


def test_remote_backup_uses_installed_gate_without_broad_sudo():
    command = resilience._remote_command(
        repo_path="/opt/aegisscan/AegisScan",
        env_path="/etc/aegisscan/production.env",
        release_sha="a" * 40,
    )
    assert command == "sudo -n /usr/local/sbin/aegisscan-production-gate backup --release-sha " + "a" * 40
    assert "sudo -n docker" not in command
    with pytest.raises(resilience.ResilienceError, match="fixed production"):
        resilience._remote_command(repo_path="/tmp/other", env_path="/etc/aegisscan/production.env", release_sha="a" * 40)


def test_trigger_requires_versioned_durable_backup_record(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "security.example.com ssh-ed25519 AAAA\n")
    monkeypatch.setattr(resilience, "_require_known_host", lambda *args, **kwargs: None)
    monkeypatch.setattr(resilience, "_resolved_enterprise_addresses", lambda *args: ["10.20.30.40"])

    payload = {
        "schema": "aegisscan.remote-backup.v1",
        "status": "success",
        "backup_id": "backup-1",
        "manifest_key": "aegisscan/postgres/backup-1/manifest.json",
        "manifest_version_id": "manifest-v1",
        "object_version_id": "object-v1",
        "source_sha256": "a" * 64,
        "release_sha": "b" * 40,
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


def test_host_backup_uses_image_entrypoint_and_rejects_unversioned_success(tmp_path, monkeypatch):
    import production_host_resilience as host
    monkeypatch.setattr(host.host, '_assert_clean_repo', lambda: None)
    monkeypatch.setattr(host.host, '_current_sha', lambda: 'a' * 40)
    monkeypatch.setattr(host.host, '_load_env_file', lambda _: {})
    monkeypatch.setattr(host.host, '_running_services', lambda *a: {'postgres'})
    state = {'status': 'success', 'backup_id': 'id', 'manifest_key': 'key',
             'manifest_version_id': 'version1', 'object_version_id': 'version2', 'source_sha256': 'b' * 64}
    calls = []
    def run(argv, **kw):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps(state))
    monkeypatch.setattr(host.host, '_run', run)
    result = host.execute(action='backup', release_sha='a' * 40, env_file=tmp_path / 'env')
    assert calls[0][-2:] == ['backup', 'once']
    assert result['release_sha'] == 'a' * 40
    state['object_version_id'] = 'null'
    with pytest.raises(host.host.DeployError, match='durable object_version_id'):
        host.execute(action='backup', release_sha='a' * 40, env_file=tmp_path / 'env')


def test_recovery_requires_actual_https_and_execution_plane_health(tmp_path, monkeypatch):
    import production_host_resilience as host
    monkeypatch.setattr(host.host, '_assert_clean_repo', lambda: None)
    monkeypatch.setattr(host.host, '_current_sha', lambda: 'a' * 40)
    monkeypatch.setattr(host.host, '_load_env_file', lambda _: {})
    monkeypatch.setattr(host.host, '_running_services', lambda *a: {'postgres'})
    calls = []
    monkeypatch.setattr(host.host, '_run', lambda argv, **kw: calls.append(argv[-2:]))
    monkeypatch.setattr(host.host, '_execution_plane_acceptance', lambda *a: calls.append('execution'))
    monkeypatch.setattr(host.host, '_accept', lambda *a: calls.append('https'))
    result = host.execute(action='recover-services', release_sha='a' * 40, env_file=tmp_path / 'env', origin='https://security.internal')
    assert calls == [['restart', 'fastapi'], 'execution', 'https']
    assert result['https_acceptance'] is True
    def unhealthy(*args):
        raise host.host.DeployError('unhealthy')
    monkeypatch.setattr(host.host, '_accept', unhealthy)
    with pytest.raises(host.host.DeployError, match='unhealthy'):
        host.execute(action='recover-services', release_sha='a' * 40, env_file=tmp_path / 'env', origin='https://security.internal')
