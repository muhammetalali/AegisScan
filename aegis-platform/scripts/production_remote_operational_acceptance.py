#!/usr/bin/env python3
"""Run post-deploy operational acceptance on an internal production host over pinned SSH."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REMOTE_DEPLOY_PATH = SCRIPT_DIR / "production_remote_deploy.py"
SPEC = importlib.util.spec_from_file_location("aegis_production_remote_deploy", REMOTE_DEPLOY_PATH)
if not SPEC or not SPEC.loader:
    raise RuntimeError("unable to load production_remote_deploy.py")
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)


class RemoteOperationalAcceptanceError(RuntimeError):
    pass


def _remote_command(*, repo_path: str, env_path: str, release_sha: str) -> str:
    q = shlex.quote
    return " && ".join(
        [
            f"cd {q(repo_path)}",
            f"test \"$(git rev-parse HEAD)\" = {q(release_sha)}",
            (
                "sudo -n python3 aegis-platform/scripts/production_operational_acceptance.py "
                f"--env-file {q(env_path)} --release-sha {q(release_sha)}"
            ),
        ]
    )


def accept_remote(
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
    try:
        host = remote._host(host)
        if port < 1 or port > 65535:
            raise remote.RemoteDeployError("SSH port must be between 1 and 65535")
        if not remote.USER_RE.fullmatch(user):
            raise remote.RemoteDeployError("SSH user is invalid")
        if not remote.SHA_RE.fullmatch(release_sha):
            raise remote.RemoteDeployError("release SHA must be exactly 40 lowercase hexadecimal characters")
        repo_path = remote._remote_path(repo_path, "remote repo path")
        env_path = remote._remote_path(env_path, "remote env path")
        private_key = private_key.resolve()
        known_hosts = known_hosts.resolve()
        remote._private_file(private_key, "SSH private key", 64 * 1024)
        remote._private_file(known_hosts, "SSH known-hosts", 1024 * 1024)
        host_addresses = remote._resolved_enterprise_addresses(host, port, "SSH host")
        remote._require_known_host(host, port, known_hosts)
    except remote.RemoteDeployError as exc:
        raise RemoteOperationalAcceptanceError(str(exc)) from exc

    command = _remote_command(repo_path=repo_path, env_path=env_path, release_sha=release_sha)
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
        detail = (exc.stderr or exc.stdout or "").strip()[-8000:]
        raise RemoteOperationalAcceptanceError(
            f"remote operational acceptance failed with exit {exc.returncode}: {detail}"
        ) from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RemoteOperationalAcceptanceError(f"remote operational acceptance failed: {exc}") from exc

    payload = None
    for line in reversed([line.strip() for line in result.stdout.splitlines() if line.strip()]):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if candidate.get("schema") == "aegisscan.production-operational-acceptance.v1":
            payload = candidate
            break
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise RemoteOperationalAcceptanceError("remote host did not return successful operational acceptance")
    if payload.get("release_sha") != release_sha:
        raise RemoteOperationalAcceptanceError("remote operational acceptance release SHA mismatch")

    return {
        "schema": "aegisscan.remote-production-operational-acceptance.v1",
        "status": "success",
        "deployment_mode": "internal",
        "host": host,
        "host_resolved_addresses": host_addresses,
        "release_sha": release_sha,
        "operational_acceptance": payload,
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
    parser.add_argument("--timeout-seconds", type=int, default=2400)
    args = parser.parse_args()
    if args.timeout_seconds < 60 or args.timeout_seconds > 7200:
        print("timeout-seconds must be between 60 and 7200", file=sys.stderr)
        return 2
    try:
        result = accept_remote(
            host=args.host,
            port=args.port,
            user=args.user,
            private_key=args.private_key,
            known_hosts=args.known_hosts,
            release_sha=args.release_sha,
            repo_path=args.repo_path,
            env_path=args.env_path,
            timeout_seconds=args.timeout_seconds,
        )
    except RemoteOperationalAcceptanceError as exc:
        print(json.dumps({
            "schema": "aegisscan.remote-production-operational-acceptance.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
