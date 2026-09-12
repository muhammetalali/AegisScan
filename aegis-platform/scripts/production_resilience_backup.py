#!/usr/bin/env python3
"""Trigger a fresh encrypted production backup on an exact-release host over pinned SSH."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from production_remote_deploy import (
    RemoteDeployError,
    SHA_RE,
    USER_RE,
    _host,
    _private_file,
    _remote_path,
    _require_known_host,
)


class ResilienceError(RuntimeError):
    pass


def _remote_command(*, repo_path: str, env_path: str, release_sha: str) -> str:
    return " && ".join(
        [
            f"cd {repo_path}",
            'test -z "$(git status --porcelain --untracked-files=no)"',
            "git fetch --no-tags origin main",
            f"test \"$(git rev-parse HEAD)\" = {release_sha}",
            f"git merge-base --is-ancestor {release_sha} origin/main",
            (
                "sudo -n docker compose "
                f"--env-file {env_path} "
                "-f aegis-platform/docker-compose.yml "
                "-f aegis-platform/docker-compose.prod.yml "
                "-f aegis-platform/docker-compose.backup.yml "
                "ps --status running --services | grep -qx postgres"
            ),
            (
                "sudo -n docker compose "
                f"--env-file {env_path} "
                "-f aegis-platform/docker-compose.yml "
                "-f aegis-platform/docker-compose.prod.yml "
                "-f aegis-platform/docker-compose.backup.yml "
                "run --rm --no-deps backup "
                "python /app/scripts/remote_backup_service.py once"
            ),
        ]
    )


def trigger(
    *,
    host: str,
    port: int,
    user: str,
    private_key: Path,
    known_hosts: Path,
    release_sha: str,
    repo_path: str,
    env_path: str,
    timeout_seconds: int,
) -> dict[str, object]:
    host = _host(host)
    if port < 1 or port > 65535:
        raise ResilienceError("SSH port must be between 1 and 65535")
    if not USER_RE.fullmatch(user):
        raise ResilienceError("SSH user is invalid")
    if not SHA_RE.fullmatch(release_sha):
        raise ResilienceError("release SHA must be exactly 40 lowercase hexadecimal characters")
    repo_path = _remote_path(repo_path, "remote repo path")
    env_path = _remote_path(env_path, "remote env path")
    _private_file(private_key, "SSH private key", 64 * 1024)
    _private_file(known_hosts, "SSH known-hosts", 1024 * 1024)
    _require_known_host(host, port, known_hosts)

    command = _remote_command(
        repo_path=repo_path,
        env_path=env_path,
        release_sha=release_sha,
    )
    argv = [
        "ssh",
        "-T",
        "-i",
        str(private_key),
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=3",
        f"{user}@{host}",
        command,
    ]
    try:
        result = subprocess.run(
            argv,
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if len(detail) > 8000:
            detail = detail[-8000:]
        raise ResilienceError(
            f"remote production backup drill failed with exit {exc.returncode}: {detail}"
        ) from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ResilienceError(f"remote production backup drill failed: {exc}") from exc

    payload = None
    for line in reversed([line.strip() for line in result.stdout.splitlines() if line.strip()]):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            candidate.get("status") == "success"
            and candidate.get("backup_id")
            and candidate.get("manifest_key")
            and candidate.get("manifest_version_id")
            and candidate.get("object_version_id")
        ):
            payload = candidate
            break

    if payload is None:
        raise ResilienceError(
            "remote host did not return a durable versioned backup success record"
        )

    return {
        "schema": "aegisscan.production-resilience-backup.v1",
        "status": "success",
        "host": host,
        "release_sha": release_sha,
        "backup": payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repo-path", default="/opt/aegisscan/AegisScan")
    parser.add_argument("--env-path", default="/etc/aegisscan/production.env")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    args = parser.parse_args()

    if args.timeout_seconds < 60 or args.timeout_seconds > 21600:
        print(json.dumps({
            "schema": "aegisscan.production-resilience-backup.v1",
            "status": "failed",
            "error": "timeout-seconds must be between 60 and 21600",
        }, sort_keys=True), file=sys.stderr)
        return 2

    try:
        result = trigger(
            host=args.host,
            port=args.port,
            user=args.user,
            private_key=args.private_key.resolve(),
            known_hosts=args.known_hosts.resolve(),
            release_sha=args.release_sha,
            repo_path=args.repo_path,
            env_path=args.env_path,
            timeout_seconds=args.timeout_seconds,
        )
    except (ResilienceError, RemoteDeployError) as exc:
        print(json.dumps({
            "schema": "aegisscan.production-resilience-backup.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
