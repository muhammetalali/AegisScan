#!/usr/bin/env python3
"""Deploy an exact AegisScan main-branch release to a prepared production host over pinned SSH."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")


class RemoteDeployError(RuntimeError):
    pass


def _private_file(path: Path, name: str, max_bytes: int) -> None:
    if not path.is_file():
        raise RemoteDeployError(f"{name} file does not exist: {path}")
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RemoteDeployError(f"{name} file must not be accessible by group or others")
    if info.st_size <= 0 or info.st_size > max_bytes:
        raise RemoteDeployError(f"{name} file has invalid size")


def _host(value: str) -> str:
    host = value.strip().lower().strip("[]")
    if not host:
        raise RemoteDeployError("SSH host is required")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host) or host.startswith(".") or host.endswith(".") or ".." in host:
            raise RemoteDeployError("SSH host is invalid")
        return host
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        raise RemoteDeployError("SSH host must not be loopback, link-local, unspecified, or multicast")
    return host


def _origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise RemoteDeployError("origin must be an explicit HTTPS origin")
    return value.strip().rstrip("/")


def _remote_path(value: str, name: str) -> str:
    path = value.strip()
    if not SAFE_PATH_RE.fullmatch(path) or "//" in path or "/../" in f"{path}/" or path.endswith("/.."):
        raise RemoteDeployError(f"{name} must be an absolute safe path")
    return path.rstrip("/") or "/"


def _remote_command(
    *,
    repo_path: str,
    env_path: str,
    release_sha: str,
    origin: str,
) -> str:
    q = shlex.quote
    return " && ".join(
        [
            f"cd {q(repo_path)}",
            "git status --porcelain --untracked-files=no | grep -q '^$'",
            "git fetch --no-tags origin main",
            f"git cat-file -e {q(release_sha + '^{commit}')}",
            f"git merge-base --is-ancestor {q(release_sha)} origin/main",
            (
                "python3 aegis-platform/scripts/production_host_reality.py "
                f"--env-file {q(env_path)}"
            ),
            (
                "python3 aegis-platform/scripts/production_host_deploy.py "
                f"--release-sha {q(release_sha)} "
                f"--env-file {q(env_path)} "
                f"--origin {q(origin)}"
            ),
        ]
    )


def deploy(
    *,
    host: str,
    port: int,
    user: str,
    private_key: Path,
    known_hosts: Path,
    release_sha: str,
    origin: str,
    repo_path: str,
    env_path: str,
    timeout_seconds: int,
) -> dict[str, object]:
    host = _host(host)
    if port < 1 or port > 65535:
        raise RemoteDeployError("SSH port must be between 1 and 65535")
    if not USER_RE.fullmatch(user):
        raise RemoteDeployError("SSH user is invalid")
    if not SHA_RE.fullmatch(release_sha):
        raise RemoteDeployError("release SHA must be exactly 40 lowercase hexadecimal characters")
    origin = _origin(origin)
    repo_path = _remote_path(repo_path, "remote repo path")
    env_path = _remote_path(env_path, "remote env path")
    _private_file(private_key, "SSH private key", 64 * 1024)
    _private_file(known_hosts, "SSH known-hosts", 1024 * 1024)

    command = _remote_command(
        repo_path=repo_path,
        env_path=env_path,
        release_sha=release_sha,
        origin=origin,
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
        raise RemoteDeployError(
            f"remote production deployment failed with exit {exc.returncode}: {detail}"
        ) from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RemoteDeployError(f"remote production deployment failed: {exc}") from exc

    result_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    deploy_payload = None
    for line in reversed(result_lines):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if candidate.get("schema") == "aegisscan.production-deploy.v1":
            deploy_payload = candidate
            break
    if not isinstance(deploy_payload, dict) or deploy_payload.get("status") != "success":
        raise RemoteDeployError("remote host did not return a successful production deployment record")

    return {
        "schema": "aegisscan.remote-production-deploy.v1",
        "status": "success",
        "host": host,
        "port": port,
        "release_sha": release_sha,
        "origin": origin,
        "remote_deployment": deploy_payload,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--repo-path", default="/opt/aegisscan/AegisScan")
    parser.add_argument("--env-path", default="/etc/aegisscan/production.env")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    args = parser.parse_args()

    if args.timeout_seconds < 60 or args.timeout_seconds > 21600:
        print(json.dumps({
            "schema": "aegisscan.remote-production-deploy.v1",
            "status": "failed",
            "error": "timeout-seconds must be between 60 and 21600",
        }, sort_keys=True), file=sys.stderr)
        return 2

    try:
        result = deploy(
            host=args.host,
            port=args.port,
            user=args.user,
            private_key=args.private_key.resolve(),
            known_hosts=args.known_hosts.resolve(),
            release_sha=args.release_sha,
            origin=args.origin,
            repo_path=args.repo_path,
            env_path=args.env_path,
            timeout_seconds=args.timeout_seconds,
        )
    except RemoteDeployError as exc:
        print(json.dumps({
            "schema": "aegisscan.remote-production-deploy.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
