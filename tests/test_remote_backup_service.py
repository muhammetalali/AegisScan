from __future__ import annotations

import json
import subprocess
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

PATH = Path(__file__).parents[1] / "aegis-platform/scripts/remote_backup_service.py"
SPEC = spec_from_file_location("remote_backup_service", PATH)
assert SPEC and SPEC.loader
service = module_from_spec(SPEC)
SPEC.loader.exec_module(service)


def _pending(tmp_path: Path) -> Path:
    backup = tmp_path / "aegisscan-aegisdb-20260910T200000Z.dump"
    backup.write_bytes(b"pending-dump")
    sidecar = Path(str(backup) + ".sha256")
    sidecar.write_text("deadbeef  " + backup.name + "\n", encoding="utf-8")
    backup.chmod(0o600)
    sidecar.chmod(0o600)
    return backup


def _configure(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AEGIS_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_BACKUP_DUMP_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("AEGIS_BACKUP_UPLOAD_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("AEGIS_BACKUP_KEEP_LOCAL_PLAINTEXT", "false")
    state_dir = tmp_path / "state"
    monkeypatch.setattr(service, "STATE_DIR", state_dir)
    monkeypatch.setattr(service, "STATE_FILE", state_dir / "last_success.json")


def test_pending_backup_is_reused_after_remote_failure(tmp_path, monkeypatch):
    _configure(monkeypatch, tmp_path)
    pending = _pending(tmp_path)
    calls = []
    fail_remote = True

    def fake_run(command, **kwargs):
        nonlocal fail_remote
        calls.append(list(command))
        assert str(service.LOCAL_BACKUP) not in command
        if fail_remote:
            fail_remote = False
            raise subprocess.CalledProcessError(1, command)
        result = {
            "backup_id": "backup-proof",
            "manifest_key": "aegisscan/postgres/backup-proof/manifest.json",
            "manifest_version_id": "manifest-v1",
            "object_version_id": "payload-v1",
            "schema": "aegisscan.remote-backup.v1",
            "source_sha256": "deadbeef",
            "status": "committed",
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(result) + "\n", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)

    with pytest.raises(subprocess.CalledProcessError):
        service.run_once()
    assert pending.is_file()
    assert Path(str(pending) + ".sha256").is_file()

    state = service.run_once()
    assert state["reused_pending_dump"] is True
    assert state["object_version_id"] == "payload-v1"
    assert not pending.exists()
    assert not Path(str(pending) + ".sha256").exists()
    assert len(calls) == 2
    assert all(str(service.LOCAL_BACKUP) not in call for call in calls)


def test_pending_backup_requires_sidecar(tmp_path):
    orphan = tmp_path / "aegisscan-aegisdb-orphan.dump"
    orphan.write_bytes(b"orphan")
    with pytest.raises(RuntimeError, match="missing SHA-256 sidecar"):
        service._pending_backup(tmp_path)


def test_orphaned_sidecar_is_rejected(tmp_path):
    sidecar = tmp_path / "aegisscan-aegisdb-orphan.dump.sha256"
    sidecar.write_text("deadbeef  missing.dump\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="sidecar has no dump"):
        service._pending_backup(tmp_path)


def test_pending_backup_uses_oldest_verified_snapshot(tmp_path):
    first = _pending(tmp_path)
    second = tmp_path / "aegisscan-aegisdb-20260910T210000Z.dump"
    second.write_bytes(b"second")
    Path(str(second) + ".sha256").write_text("beadfeed  " + second.name + "\n", encoding="utf-8")
    first.touch()
    second.touch()
    import os
    os.utime(first, (1, 1))
    os.utime(second, (2, 2))
    assert service._pending_backup(tmp_path) == first.resolve()
