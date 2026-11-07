#!/usr/bin/env python3
"""Read-only G5 scheduler evidence collector; does NOT prove restore, RPO or RTO.

Run on the authorized production host after the second genuine daily scheduler
cycle. Reads only exact-release Git metadata, selected Docker inspect fields,
Docker scheduler stdout and its interval. Never triggers backups or restarts.
The immutable, redacted receipt is a *candidate* for independent verification.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PRODUCTION_REPO = Path("/opt/aegisscan/AegisScan")
SCHEDULER_CONTAINER = "aegis-remote-backup"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_LOG_BYTES = 8 * 1024 * 1024
TOLERANCE_SECONDS = 900


class EvidenceError(ValueError):
    pass


def _utc(value: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("invalid UTC time")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid UTC time") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset().total_seconds() != 0:
        raise EvidenceError("explicit UTC time required")
    return timestamp.astimezone(timezone.utc)


def _run(args: list[str], *, limit: int = MAX_LOG_BYTES, timeout: int = 30) -> str:
    result = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        # Never echo shell/docker error output: it might contain environment data.
        raise EvidenceError(f"read-only probe failed: {args[0]} (exit={result.returncode})")
    if len(result.stdout) > limit:
        raise EvidenceError("read-only probe output exceeds size limit")
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError("read-only probe returned non-UTF8 data") from exc


def parse_inspect(text: str) -> dict:
    try:
        cid, started, restarts, running, command, entrypoint = text.strip().split("|", 5)
        cmd = json.loads(command)
        entry = json.loads(entrypoint)
        restart_count = int(restarts)
        started_at = _utc(started)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("invalid selected container inspection") from exc
    if not SHA64.fullmatch(cid):
        raise EvidenceError("invalid container ID")
    if running != "true" or restart_count != 0:
        raise EvidenceError("scheduler has stopped or restarted; continuity cannot be asserted")
    if cmd != ["schedule"] or entry != ["python3", "/app/scripts/remote_backup_service.py"]:
        raise EvidenceError("container is not the approved schedule-mode process")
    return {"container_id": cid, "started_at": started_at, "restart_count": restart_count}


def parse_scheduler_logs(logs: str, *, inspect: dict, collected_at: datetime) -> tuple[list[dict], int]:
    """Only lines in this *specific schedule container's* daemon logs qualify.

    The `origin` field below is inferred from the verified container command and
    log provenance; the backup JSON alone does not encode schedule vs `once`.
    """
    events: list[dict] = []
    failures = 0
    seen: set[str] = set()
    for line in logs.splitlines():
        try:
            log_time, message = line.split(" ", 1)
            recorded = _utc(log_time)
            data = json.loads(message)
        except (ValueError, json.JSONDecodeError, TypeError, EvidenceError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("status") == "failed":
            failures += 1
            continue
        if data.get("status") != "success" or data.get("schema") != "aegisscan.remote-backup.v1":
            continue
        if not all(isinstance(data.get(k), str) and data[k] for k in
                   ("backup_id", "manifest_version_id", "object_version_id")):
            continue
        if not SHA64.fullmatch(str(data.get("source_sha256", ""))):
            continue
        try:
            completed = _utc(data["completed_at"])
        except (KeyError, EvidenceError, TypeError):
            continue
        if not (inspect["started_at"] <= recorded <= collected_at):
            continue
        if abs((recorded - completed).total_seconds()) > 120:
            continue
        if data["backup_id"] in seen:
            raise EvidenceError("duplicate backup ID in schedule container stdout")
        seen.add(data["backup_id"])
        events.append({
            "origin": "schedule",
            "status": "success",
            "scheduler_instance_id": inspect["container_id"],
            "backup_id": data["backup_id"],
            "completed_at": completed.isoformat().replace("+00:00", "Z"),
            "docker_log_at": recorded.isoformat().replace("+00:00", "Z"),
            "manifest_version_id": data["manifest_version_id"],
            "object_version_id": data["object_version_id"],
            "source_sha256": data["source_sha256"],
        })
    events.sort(key=lambda item: item["completed_at"])
    return events, failures


def make_receipt(*, expected_release_sha: str, actual_release_sha: str,
                 checkout_clean: bool, inspection_text: str, logs: str,
                 interval_seconds: int, collected_at: datetime) -> dict:
    if not SHA40.fullmatch(expected_release_sha) or actual_release_sha != expected_release_sha:
        raise EvidenceError("release SHA mismatch: fail closed")
    if not checkout_clean:
        raise EvidenceError("production Git checkout is not clean")
    if interval_seconds != 86400:
        raise EvidenceError("schedule interval does not equal 86400 seconds")
    inspected = parse_inspect(inspection_text)
    events, failed_count = parse_scheduler_logs(logs, inspect=inspected, collected_at=collected_at)
    pair_ok = False
    if len(events) >= 2:
        first, second = events[-2:]
        spacing = (_utc(second["completed_at"]) - _utc(first["completed_at"])).total_seconds()
        pair_ok = (
            first["backup_id"] != second["backup_id"]
            and first["manifest_version_id"] != second["manifest_version_id"]
            and first["object_version_id"] != second["object_version_id"]
            and abs(spacing - interval_seconds) <= TOLERANCE_SECONDS
        )
    return {
        "schema": "aegisscan.g5-schedule-runtime-receipt.v1",
        "status": "CANDIDATE_TWO_CYCLES" if pair_ok else "PARTIAL_NEEDS_TWO_CYCLES",
        "g5_accepted": False,
        "scope": "scheduler_origin_and_interval_only",
        "release_sha": expected_release_sha,
        "collected_at": collected_at.isoformat().replace("+00:00", "Z"),
        "collector_source": "live_docker_inspect_and_daemon_logs",
        "scheduler_container_id": inspected["container_id"],
        "scheduler_started_at": inspected["started_at"].isoformat().replace("+00:00", "Z"),
        "scheduler_restart_count": inspected["restart_count"],
        "interval_seconds": interval_seconds,
        "docker_logs_sha256": hashlib.sha256(logs.encode("utf-8")).hexdigest(),
        "docker_inspection_sha256": hashlib.sha256(inspection_text.encode("utf-8")).hexdigest(),
        "backup_failure_line_count": failed_count,
        "automatic_backup_events": events,
        "two_cycle_candidate": pair_ok,
        "unverified_gates": ["latest_scheduled_isolated_restore", "six_service_isolated_recovery", "owner_signed_numeric_rpo_rto"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-release-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        repo = str(PRODUCTION_REPO)
        sha = _run(["git", "-c", f"safe.directory={repo}", "-C", repo, "rev-parse", "HEAD"], limit=128).strip()
        dirty = _run(["git", "-c", f"safe.directory={repo}", "-C", repo, "status", "--porcelain"], limit=1_000_000)
        # Selected fields only: never capture or emit the container's credentials or environment.
        format_string = ("{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.State.Running}}|"
                         "{{json .Config.Cmd}}|{{json .Config.Entrypoint}}")
        raw_inspection = _run(["docker", "inspect", "--format", format_string, SCHEDULER_CONTAINER], limit=2048)
        inspection = parse_inspect(raw_inspection)
        # Only the single explicitly allowlisted interval value is read inside the container.
        interval = _run(["docker", "exec", SCHEDULER_CONTAINER, "python3", "-c",
                         "import os; print(os.environ.get('AEGIS_BACKUP_INTERVAL_SECONDS', '86400'))"], limit=32)
        if not interval.strip().isdigit():
            raise EvidenceError("invalid read-only scheduler interval")
        raw_logs = _run(["docker", "logs", "--timestamps", "--since",
                         inspection["started_at"].isoformat(), SCHEDULER_CONTAINER], timeout=60)
        receipt = make_receipt(
            expected_release_sha=args.expected_release_sha,
            actual_release_sha=sha, checkout_clean=not dirty.strip(),
            inspection_text=raw_inspection, logs=raw_logs,
            interval_seconds=int(interval.strip()), collected_at=datetime.now(timezone.utc),
        )
        output = args.output
        if output.exists() or output.is_symlink():
            raise EvidenceError("output already exists: immutable evidence must not be overwritten")
        os.umask(0o077)
        with output.open("x", encoding="utf-8") as file:
            file.write(json.dumps(receipt, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
            file.flush()
            os.fsync(file.fileno())
        print(json.dumps({"status": receipt["status"], "output": str(output),
                          "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                          "scheduled_events": len(receipt["automatic_backup_events"]),
                          "g5_accepted": False}, sort_keys=True))
        return 0 if receipt["two_cycle_candidate"] else 2
    except (EvidenceError, OSError, subprocess.TimeoutExpired) as exc:
        # Do not echo raw exceptions from Docker, which may contain env data.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                          "reason": str(exc) if isinstance(exc, EvidenceError) else "read_only_capture_failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
