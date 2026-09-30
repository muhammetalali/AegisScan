#!/usr/bin/env python3
"""Fixed, exact-release backup and application recovery actions for the installed gate."""
from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import production_host_deploy as host


def _backup_db_network() -> str:
    result = host._run(
        [
            "docker", "inspect", "-f",
            "{{range $name, $cfg := .NetworkSettings.Networks}}{{println $name}}{{end}}",
            "aegis-remote-backup",
        ],
        cwd=host.PLATFORM_DIR,
        timeout=60,
    )
    networks = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    matches = [name for name in networks if name.endswith("_backup_db")]
    if len(matches) != 1:
        raise host.DeployError("cannot identify the isolated production backup database network")
    return matches[0]


def _production_postgres_image_id() -> str:
    result = host._run(
        ["docker", "inspect", "-f", "{{.Image}}", "aegis-postgres"],
        cwd=host.PLATFORM_DIR,
        timeout=60,
    )
    image_id = result.stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise host.DeployError("production PostgreSQL immutable image ID is invalid")
    return image_id


def _wait_disposable_postgres(name: str, *, attempts: int = 60) -> None:
    for _ in range(attempts):
        probe = subprocess.run(
            ["docker", "exec", name, "pg_isready", "-U", "aegis", "-d", "aegis_restore_control"],
            cwd=host.PLATFORM_DIR,
            text=True,
            capture_output=True,
            timeout=10,
        )
        if probe.returncode == 0:
            return
        time.sleep(1)
    logs = subprocess.run(
        ["docker", "logs", "--tail", "80", name],
        cwd=host.PLATFORM_DIR, text=True, capture_output=True, timeout=15,
    )
    raise host.DeployError(
        "disposable PostgreSQL did not become ready for restore verification: "
        + (logs.stderr or logs.stdout)[-4000:]
    )


def _restore_drill(
    *,
    backup: dict[str, object],
    env_file: Path,
    env: dict[str, str],
) -> dict[str, object]:
    network = _backup_db_network()
    postgres_image_id = _production_postgres_image_id()
    suffix = secrets.token_hex(8)
    name = f"aegis-resilience-restore-{suffix}"
    alias = f"restore-{suffix}"
    password = secrets.token_urlsafe(32)
    drill_env = dict(env)
    drill_env["POSTGRES_PASSWORD"] = password
    started = False
    try:
        host._run(
            [
                "docker", "run", "-d", "--name", name,
                "--network", network, "--network-alias", alias,
                "--user", "70:70", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--pids-limit", "128", "--memory", "512m", "--cpus", "1",
                "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=2147483648,uid=70,gid=70,mode=0700",
                "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16777216,uid=70,gid=70,mode=0755",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=67108864,uid=70,gid=70,mode=0700",
                "-e", "POSTGRES_USER=aegis",
                "-e", "POSTGRES_PASSWORD",
                "-e", "POSTGRES_DB=aegis_restore_control",
                postgres_image_id,
            ],
            cwd=host.PLATFORM_DIR, env=drill_env, timeout=120,
        )
        started = True
        _wait_disposable_postgres(name)

        script = (
            "set -eu; "
            "work=/tmp/aegis-resilience-restore; "
            "rm -rf \"$work\"; mkdir -p \"$work\"; chmod 0700 \"$work\"; "
            "python3 /app/scripts/remote_backup.py restore "
            "--manifest-key \"$1\" --manifest-version-id \"$2\" "
            "--output \"$work/production.dump\" --work-dir \"$work\"; "
            "/app/scripts/verify_postgres_restore.sh \"$work/production.dump\""
        )
        result = host._run(
            host._compose(
                env_file,
                "run", "--rm", "--no-deps",
                "-e", f"PGHOST={alias}",
                "-e", "PGPORT=5432",
                "-e", "PGUSER=aegis",
                "-e", "AEGIS_RESTORE_REQUIRED_TABLES=django_migrations,users_user",
                "--entrypoint", "/bin/sh",
                "backup", "-ec", script, "sh",
                str(backup["manifest_key"]), str(backup["manifest_version_id"]),
            ),
            cwd=host.PLATFORM_DIR, env=drill_env, timeout=14400,
        )
        restore: dict[str, object] | None = None
        for line in reversed([line.strip() for line in result.stdout.splitlines() if line.strip()]):
            if not line.startswith("{"):
                continue
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and candidate.get("status") == "restored-locally":
                restore = candidate
                break
        if restore is None or "RESTORE_VERIFICATION=PASS" not in result.stdout:
            raise host.DeployError("remote backup restore drill did not prove PostgreSQL recovery")
        for field in ("backup_id", "manifest_version_id", "object_version_id", "source_sha256"):
            if str(restore.get(field, "")) != str(backup.get(field, "")):
                raise host.DeployError(f"remote restore drill does not match backup {field}")
        return {
            "status": "success",
            "backup_id": restore["backup_id"],
            "manifest_version_id": restore["manifest_version_id"],
            "object_version_id": restore["object_version_id"],
            "source_sha256": restore["source_sha256"],
            "postgres_restore_verified": True,
            "required_tables": ["django_migrations", "users_user"],
            "network_scope": "isolated-backup-db",
            "plaintext_scope": "ephemeral-backup-container-tmpfs",
            "postgres_image_id": postgres_image_id,
        }
    finally:
        if started:
            active_failure = sys.exc_info()[1]
            try:
                cleanup = subprocess.run(
                    ["docker", "rm", "-f", name],
                    cwd=host.PLATFORM_DIR, text=True, capture_output=True, timeout=60,
                )
                cleanup_error = (
                    None
                    if cleanup.returncode == 0
                    else "failed to remove disposable PostgreSQL after restore verification: "
                    + cleanup.stderr[-2000:]
                )
            except (OSError, subprocess.SubprocessError) as exc:
                cleanup_error = f"disposable PostgreSQL cleanup command failed: {exc}"
            if cleanup_error:
                if active_failure is not None:
                    raise host.DeployError(
                        f"{active_failure}; cleanup also failed: {cleanup_error}"
                    ) from active_failure
                raise host.DeployError(cleanup_error)


def execute(*, action: str, release_sha: str, env_file: Path, origin: str = "") -> dict:
    if not host.SHA_RE.fullmatch(release_sha) or action not in {"backup", "recover-services"}:
        raise host.DeployError("invalid resilience action or release SHA")
    host._assert_clean_repo()
    if host._current_sha() != release_sha:
        raise host.DeployError("production host checkout does not match the resilience release SHA")
    env = host._execution_profile_environment(host._load_env_file(env_file))
    # The privileged gate supplies a sanitized PATH and CA trust. Keep those values.
    env = {**host.os.environ, **env}
    if "postgres" not in host._running_services(env_file, env):
        raise host.DeployError("production PostgreSQL is not running")
    if action == "backup":
        result = host._run(host._compose(env_file, "run", "--rm", "--no-deps", "backup", "once"),
                           cwd=host.PLATFORM_DIR, env=env, timeout=14400)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        try:
            payload = json.loads(lines[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise host.DeployError("backup did not return durable JSON") from exc
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise host.DeployError("backup did not succeed")
        for key in ("backup_id", "manifest_key", "manifest_version_id", "object_version_id"):
            if not payload.get(key) or payload[key] == "null":
                raise host.DeployError(f"backup is missing durable {key}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("source_sha256", ""))):
            raise host.DeployError("backup source digest is invalid")
        payload["restore_verification"] = _restore_drill(backup=payload, env_file=env_file, env=env)
        payload["release_sha"] = release_sha
    else:
        origin = host._validate_origin(origin)
        host._run(host._compose(env_file, "restart", "fastapi"), cwd=host.PLATFORM_DIR, env=env, timeout=180)
        host._execution_plane_acceptance(env_file, env)
        host._accept(origin)
        alert_delivery = host._alert_delivery_acceptance(env_file, env, release_sha)
        payload = {"schema": "aegisscan.production-service-recovery.v1", "status": "success",
                   "release_sha": release_sha, "restarted_services": ["fastapi"],
                   "https_acceptance": True, "execution_plane_healthy": True,
                   "alert_delivery": alert_delivery}
    if host._current_sha() != release_sha:
        raise host.DeployError("production release changed during resilience acceptance")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["backup", "recover-services"], required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--origin", default="")
    args = parser.parse_args()
    try:
        result = execute(action=args.action, release_sha=args.release_sha, env_file=args.env_file, origin=args.origin)
    except (host.DeployError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
