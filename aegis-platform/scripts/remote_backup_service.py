#!/usr/bin/env python3
"""Run verified PostgreSQL backups and commit them to encrypted remote storage."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

os.umask(0o077)

SCRIPT_DIR = Path(__file__).resolve().parent
LOCAL_BACKUP = SCRIPT_DIR / "backup_postgres.sh"
REMOTE_BACKUP = SCRIPT_DIR / "remote_backup.py"
STATE_DIR = Path(os.getenv("AEGIS_BACKUP_STATE_DIR", "/run/aegis-backup"))
STATE_FILE = STATE_DIR / "last_success.json"


def _truthy(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _seconds(name: str, default: int, minimum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _publish_state(payload: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_DIR / ".last_success.partial"
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, STATE_FILE)
    STATE_FILE.chmod(0o600)



def _pending_backup(backup_dir: Path) -> Path | None:
    candidates: list[Path] = []
    dumps = sorted(backup_dir.glob("aegisscan-*.dump"))
    sidecars = sorted(backup_dir.glob("aegisscan-*.dump.sha256"))

    for candidate in dumps:
        resolved = candidate.resolve()
        if resolved.parent != backup_dir or not resolved.is_file():
            raise RuntimeError("pending backup path escaped the configured backup directory")
        sidecar = Path(str(resolved) + ".sha256")
        if not sidecar.is_file():
            raise RuntimeError("pending backup is missing SHA-256 sidecar")
        candidates.append(resolved)

    for sidecar in sidecars:
        dump = Path(str(sidecar)[:-7])
        if not dump.is_file():
            raise RuntimeError("orphaned backup SHA-256 sidecar has no dump")

    if not candidates:
        return None
    candidates.sort(key=lambda path: (path.stat().st_mtime_ns, path.name))
    return candidates[0]


def run_once() -> dict:
    backup_dir = Path(os.environ["AEGIS_BACKUP_DIR"]).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    source = _pending_backup(backup_dir)
    reused_pending = source is not None
    if source is None:
        backup = subprocess.run(
            ["sh", str(LOCAL_BACKUP)],
            check=True,
            capture_output=True,
            text=True,
            timeout=_seconds("AEGIS_BACKUP_DUMP_TIMEOUT_SECONDS", 7200, 60),
        )
        lines = [line.strip() for line in backup.stdout.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("local backup script did not return a backup path")
        source = Path(lines[-1]).resolve()
        if source.parent != backup_dir or not source.is_file():
            raise RuntimeError("local backup path escaped the configured backup directory")

    command = [
        sys.executable,
        str(REMOTE_BACKUP),
        "push",
        "--source",
        str(source),
        "--work-dir",
        str(backup_dir),
    ]
    if _truthy("AEGIS_BACKUP_ALLOW_HTTP_TEST_ONLY"):
        command.append("--allow-http")
    remote = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=_seconds("AEGIS_BACKUP_UPLOAD_TIMEOUT_SECONDS", 7200, 60),
    )
    result_lines = [line.strip() for line in remote.stdout.splitlines() if line.strip()]
    if not result_lines:
        raise RuntimeError("remote backup transport returned no result")
    result = json.loads(result_lines[-1])
    if result.get("status") != "committed":
        raise RuntimeError("remote backup transport did not commit the backup")

    if not _truthy("AEGIS_BACKUP_KEEP_LOCAL_PLAINTEXT"):
        source.unlink(missing_ok=True)
        Path(str(source) + ".sha256").unlink(missing_ok=True)

    state = {
        "backup_id": result["backup_id"],
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "manifest_key": result["manifest_key"],
        "manifest_version_id": result["manifest_version_id"],
        "reused_pending_dump": reused_pending,
        "object_version_id": result["object_version_id"],
        "schema": result["schema"],
        "source_sha256": result["source_sha256"],
        "status": "success",
    }
    _publish_state(state)
    print(json.dumps(state, sort_keys=True), flush=True)
    return state


def health() -> int:
    if not STATE_FILE.is_file():
        print("backup has not completed successfully", file=sys.stderr)
        return 1
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        completed = datetime.fromisoformat(str(state["completed_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"backup state is invalid: {exc}", file=sys.stderr)
        return 1
    age = (datetime.now(timezone.utc) - completed).total_seconds()
    interval = _seconds("AEGIS_BACKUP_INTERVAL_SECONDS", 86400, 3600)
    max_age = interval * 2 + 900
    if age < 0 or age > max_age:
        print(f"last successful remote backup is stale: age={int(age)}s", file=sys.stderr)
        return 1
    print(json.dumps({"status": "healthy", "backup_id": state.get("backup_id"), "age_seconds": int(age)}))
    return 0


def schedule() -> int:
    interval = _seconds("AEGIS_BACKUP_INTERVAL_SECONDS", 86400, 3600)
    retry = _seconds("AEGIS_BACKUP_RETRY_SECONDS", 300, 60)
    while True:
        try:
            run_once()
            delay = interval
        except Exception as exc:
            print(json.dumps({"status": "failed", "error": str(exc)}), file=sys.stderr, flush=True)
            delay = retry
        time.sleep(delay)


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "schedule"
    if command == "once":
        run_once()
        return 0
    if command == "health":
        return health()
    if command == "schedule":
        return schedule()
    print("usage: remote_backup_service.py [once|schedule|health]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
