#!/usr/bin/env python3
"""Trigger a fresh encrypted production backup on an exact-release host over pinned SSH."""
from __future__ import annotations

import argparse
import json
import shlex
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
    _resolved_enterprise_addresses,
    _known_host_lookup,
    _origin,
    PRIVILEGED_GATE,
    PRODUCTION_REPO_PATH,
    PRODUCTION_ENV_PATH,
)


class ResilienceError(RuntimeError):
    pass


def _remote_command(*, repo_path: str, env_path: str, release_sha: str,
                    action: str = "backup", origin: str = "") -> str:
    if repo_path != PRODUCTION_REPO_PATH or env_path != PRODUCTION_ENV_PATH:
        raise ResilienceError("resilience requires the fixed production repository and environment")
    if action not in {"backup", "recover-services"}:
        raise ResilienceError("unsupported resilience action")
    command = f"sudo -n {shlex.quote(PRIVILEGED_GATE)} {action} --release-sha {shlex.quote(release_sha)}"
    if action == "recover-services":
        command += f" --origin {shlex.quote(_origin(origin))}"
    return command


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
    action: str = "backup",
    origin: str = "",
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
    addresses = _resolved_enterprise_addresses(host, port, "SSH host")
    host_key_alias = _require_known_host(host, port, known_hosts, resolved_addresses=addresses)

    command = _remote_command(
        repo_path=repo_path,
        env_path=env_path,
        release_sha=release_sha, action=action, origin=origin,
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
        *(["-o", f"HostKeyAlias={host_key_alias}"]
          if host_key_alias and host_key_alias != _known_host_lookup(host, port) else []),
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
        if not isinstance(candidate, dict) or candidate.get("release_sha") != release_sha:
            continue
        if action == "recover-services":
            if (candidate.get("schema") == "aegisscan.production-service-recovery.v1"
                and candidate.get("status") == "success"
                and candidate.get("https_acceptance") is True
                and candidate.get("execution_plane_healthy") is True
                and candidate.get("restarted_services") == ["fastapi"]):
                payload = candidate
                break
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
        raise ResilienceError("remote host did not return a durable versioned backup or recovery success record")

    return {
        "schema": f"aegisscan.production-resilience-{'backup' if action == 'backup' else 'recovery'}.v1",
        "status": "success",
        "host": host,
        "release_sha": release_sha,
        "backup" if action == "backup" else "recovery": payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["backup", "recover-services"], default="backup")
    parser.add_argument("--origin", default="")
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
            timeout_seconds=args.timeout_seconds, action=args.action, origin=args.origin,
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
