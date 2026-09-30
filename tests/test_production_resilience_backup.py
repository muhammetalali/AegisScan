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
        "restore_verification": {
            "status": "success",
            "backup_id": "backup-1",
            "manifest_version_id": "manifest-v1",
            "object_version_id": "object-v1",
            "source_sha256": "a" * 64,
            "postgres_restore_verified": True,
            "network_scope": "isolated-backup-db",
            "plaintext_scope": "ephemeral-backup-container-tmpfs",
            "postgres_image_id": "sha256:" + "a" * 64,
        },
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
    monkeypatch.setattr(host, '_restore_drill', lambda **_: {
        'status': 'success', 'backup_id': 'id', 'manifest_version_id': 'version1',
        'object_version_id': 'version2', 'source_sha256': 'b' * 64,
        'postgres_restore_verified': True, 'network_scope': 'isolated-backup-db',
        'plaintext_scope': 'ephemeral-backup-container-tmpfs',
        'postgres_image_id': 'sha256:' + 'a' * 64,
    })
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
    assert result['restore_verification']['postgres_restore_verified'] is True
    state['object_version_id'] = 'null'
    with pytest.raises(host.host.DeployError, match='durable object_version_id'):
        host.execute(action='backup', release_sha='a' * 40, env_file=tmp_path / 'env')


def test_host_restore_drill_uses_running_production_postgres_image_id(monkeypatch):
    import production_host_resilience as host

    monkeypatch.setattr(
        host.host, '_run',
        lambda argv, **kwargs: SimpleNamespace(stdout='sha256:' + 'a' * 64 + '\n'),
    )
    assert host._production_postgres_image_id() == 'sha256:' + 'a' * 64

    monkeypatch.setattr(
        host.host, '_run',
        lambda argv, **kwargs: SimpleNamespace(stdout='postgres:16-alpine\n'),
    )
    with pytest.raises(host.host.DeployError, match='immutable image ID'):
        host._production_postgres_image_id()


def test_host_restore_drill_is_isolated_bounded_and_matches_exact_backup(tmp_path, monkeypatch):
    import production_host_resilience as host

    backup = {
        'backup_id': 'backup-1',
        'manifest_key': 'aegisscan/postgres/backup-1/manifest.json',
        'manifest_version_id': 'manifest-v1',
        'object_version_id': 'object-v1',
        'source_sha256': 'c' * 64,
    }
    monkeypatch.setattr(host, '_backup_db_network', lambda: 'aegis-platform_backup_db')
    monkeypatch.setattr(host, '_production_postgres_image_id', lambda: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(host, '_wait_disposable_postgres', lambda name: None)
    monkeypatch.setattr(host.secrets, 'token_hex', lambda _n: '1234567890abcdef')
    monkeypatch.setattr(host.secrets, 'token_urlsafe', lambda _n: 'disposable-restore-password')
    monkeypatch.setattr(host.host, '_compose', lambda _env, *args: ['docker', 'compose', *args])

    calls = []
    restore = {
        'status': 'restored-locally',
        'backup_id': 'backup-1',
        'manifest_version_id': 'manifest-v1',
        'object_version_id': 'object-v1',
        'source_sha256': 'c' * 64,
    }

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ['docker', 'run']:
            return SimpleNamespace(stdout='container-id\n')
        return SimpleNamespace(stdout=json.dumps(restore) + '\nRESTORE_VERIFICATION=PASS database=proof\n')

    cleanup = []
    monkeypatch.setattr(host.host, '_run', fake_run)
    monkeypatch.setattr(
        host.subprocess, 'run',
        lambda argv, **kwargs: cleanup.append(argv) or SimpleNamespace(returncode=0, stdout='', stderr=''),
    )

    result = host._restore_drill(backup=backup, env_file=tmp_path / 'env', env={})
    docker_run = calls[0]
    assert '--network' in docker_run and 'aegis-platform_backup_db' in docker_run
    assert '--read-only' in docker_run
    assert ['--cap-drop', 'ALL'] == docker_run[docker_run.index('--cap-drop'):docker_run.index('--cap-drop') + 2]
    assert '--pids-limit' in docker_run and '--memory' in docker_run and '--cpus' in docker_run
    assert '-p' not in docker_run and '--publish' not in docker_run
    assert docker_run[-1] == 'sha256:' + 'a' * 64
    assert 'disposable-restore-password' not in ' '.join(docker_run)
    compose_run = calls[1]
    assert '--no-deps' in compose_run
    assert '--entrypoint' in compose_run and '/bin/sh' in compose_run
    assert 'backup' in compose_run
    assert 'disposable-restore-password' not in ' '.join(compose_run)
    assert result['postgres_restore_verified'] is True
    assert result['network_scope'] == 'isolated-backup-db'
    assert result['plaintext_scope'] == 'ephemeral-backup-container-tmpfs'
    assert result['postgres_image_id'] == 'sha256:' + 'a' * 64
    assert cleanup[-1][:3] == ['docker', 'rm', '-f']


def test_host_restore_drill_preserves_primary_failure_when_cleanup_also_fails(tmp_path, monkeypatch):
    import production_host_resilience as host

    backup = {
        'backup_id': 'backup-1',
        'manifest_key': 'aegisscan/postgres/backup-1/manifest.json',
        'manifest_version_id': 'manifest-v1',
        'object_version_id': 'object-v1',
        'source_sha256': 'c' * 64,
    }
    monkeypatch.setattr(host, '_backup_db_network', lambda: 'aegis-platform_backup_db')
    monkeypatch.setattr(host, '_production_postgres_image_id', lambda: 'sha256:' + 'a' * 64)
    monkeypatch.setattr(host, '_wait_disposable_postgres', lambda name: None)
    monkeypatch.setattr(host.secrets, 'token_hex', lambda _n: '1234567890abcdef')
    monkeypatch.setattr(host.secrets, 'token_urlsafe', lambda _n: 'disposable-restore-password')
    monkeypatch.setattr(host.host, '_compose', lambda _env, *args: ['docker', 'compose', *args])
    original = host.host.DeployError('restore execution failed')
    calls = {'count': 0}

    def fake_run(argv, **kwargs):
        calls['count'] += 1
        if calls['count'] == 1:
            return SimpleNamespace(stdout='container-id\n')
        raise original

    monkeypatch.setattr(host.host, '_run', fake_run)
    monkeypatch.setattr(
        host.subprocess, 'run',
        lambda argv, **kwargs: SimpleNamespace(returncode=1, stdout='', stderr='cleanup denied'),
    )

    with pytest.raises(host.host.DeployError) as exc:
        host._restore_drill(backup=backup, env_file=tmp_path / 'env', env={})
    assert 'restore execution failed' in str(exc.value)
    assert 'cleanup also failed' in str(exc.value)
    assert 'cleanup denied' in str(exc.value)
    assert exc.value.__cause__ is original


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
    monkeypatch.setattr(
        host.host,
        '_alert_delivery_acceptance',
        lambda *a: calls.append('alerts') or {
            'status': 'success', 'authenticated': True, 'transport': 'https', 'receiver': 'internal',
            'baseline_events': 1.0, 'current_events': 2.0,
            'proof_alertname': 'AegisProductionAlertDeliveryAcceptance',
            'proof_release_sha': 'a' * 40, 'audit_payload_sha256': 'f' * 64,
        },
    )
    result = host.execute(action='recover-services', release_sha='a' * 40, env_file=tmp_path / 'env', origin='https://security.internal')
    assert calls == [['restart', 'fastapi'], 'execution', 'https', 'alerts']
    assert result['https_acceptance'] is True
    assert result['alert_delivery']['authenticated'] is True
    def unhealthy(*args):
        raise host.host.DeployError('unhealthy')
    monkeypatch.setattr(host.host, '_accept', unhealthy)
    with pytest.raises(host.host.DeployError, match='unhealthy'):
        host.execute(action='recover-services', release_sha='a' * 40, env_file=tmp_path / 'env', origin='https://security.internal')


def test_trigger_recovery_requires_authenticated_internal_alert_delivery(tmp_path: Path, monkeypatch):
    key = _private(tmp_path / "id", "private")
    known = _private(tmp_path / "known_hosts", "security.example.com ssh-ed25519 AAAA\n")
    monkeypatch.setattr(resilience, "_require_known_host", lambda *args, **kwargs: None)
    monkeypatch.setattr(resilience, "_resolved_enterprise_addresses", lambda *args: ["10.20.30.40"])
    release = "b" * 40
    good = {
        "schema": "aegisscan.production-service-recovery.v1",
        "status": "success",
        "release_sha": release,
        "restarted_services": ["fastapi"],
        "https_acceptance": True,
        "execution_plane_healthy": True,
        "alert_delivery": {
            "status": "success",
            "authenticated": True,
            "transport": "https",
            "receiver": "internal",
            "proof_alertname": "AegisProductionAlertDeliveryAcceptance",
            "proof_release_sha": release,
            "audit_payload_sha256": "e" * 64,
        },
    }
    monkeypatch.setattr(resilience.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(good)+"\n"))
    result = resilience.trigger(
        host="security.example.com", port=22, user="aegis", private_key=key, known_hosts=known,
        release_sha=release, repo_path="/opt/aegisscan/AegisScan", env_path="/etc/aegisscan/production.env",
        timeout_seconds=120, action="recover-services", origin="https://security.example.com",
    )
    assert result["recovery"]["alert_delivery"]["authenticated"] is True

    bad = dict(good)
    bad["alert_delivery"] = {"status": "success", "authenticated": False, "transport": "https", "receiver": "internal"}
    monkeypatch.setattr(resilience.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(bad)+"\n"))
    with pytest.raises(resilience.ResilienceError, match="durable versioned backup or recovery success"):
        resilience.trigger(
            host="security.example.com", port=22, user="aegis", private_key=key, known_hosts=known,
            release_sha=release, repo_path="/opt/aegisscan/AegisScan", env_path="/etc/aegisscan/production.env",
            timeout_seconds=120, action="recover-services", origin="https://security.example.com",
        )
