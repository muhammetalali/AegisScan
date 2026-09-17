#!/usr/bin/env python3
"""Deploy an exact AegisScan main-branch release to an internal production host over pinned SSH."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")


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


def _is_enterprise_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS)
    return address in IPV6_ULA


def _resolved_enterprise_addresses(host: str, port: int, label: str) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = {literal}
    else:
        try:
            resolved = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise RemoteDeployError(f"{label} private DNS resolution failed for {host}: {exc}") from exc
        addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for item in resolved:
            sockaddr = item[4]
            if not sockaddr:
                continue
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError as exc:
                raise RemoteDeployError(f"{label} resolver returned an invalid address: {sockaddr[0]!r}") from exc
    if not addresses:
        raise RemoteDeployError(f"{label} private DNS returned no addresses for {host}")
    invalid = sorted(str(address) for address in addresses if not _is_enterprise_private(address))
    if invalid:
        raise RemoteDeployError(
            f"{label} resolved outside RFC1918/IPv6-ULA perimeter: " + ", ".join(invalid)
        )
    return sorted(str(address) for address in addresses)


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
    if not _is_enterprise_private(address):
        raise RemoteDeployError("SSH host literal must be inside the RFC1918/IPv6-ULA enterprise perimeter")
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
    host = parsed.hostname.strip().lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise RemoteDeployError("origin port is invalid") from exc
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host) or host.startswith(".") or host.endswith(".") or ".." in host:
            raise RemoteDeployError("origin hostname is invalid")
        url_host = host
    else:
        if not _is_enterprise_private(address):
            raise RemoteDeployError("origin literal must be inside the RFC1918/IPv6-ULA enterprise perimeter")
        url_host = f"[{host}]" if isinstance(address, ipaddress.IPv6Address) else host
    port_part = f":{port}" if port and port != 443 else ""
    return f"https://{url_host}{port_part}"


def _require_known_host(host: str, port: int, known_hosts: Path) -> None:
    lookup = host if port == 22 else f"[{host}]:{port}"
    try:
        result = subprocess.run(
            ["ssh-keygen", "-F", lookup, "-f", str(known_hosts)],
            check=False,
            text=True,
            capture_output=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RemoteDeployError(f"unable to validate pinned SSH host key: {exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise RemoteDeployError(f"SSH known-hosts does not contain a pinned entry for {lookup}")


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
            "test -z \"$(git status --porcelain --untracked-files=no)\"",
            "git fetch --no-tags origin main",
            f"git cat-file -e {q(release_sha + '^{commit}')}",
            f"git merge-base --is-ancestor {q(release_sha)} origin/main",
            (
                "sudo -n python3 aegis-platform/scripts/production_host_reality.py "
                f"--env-file {q(env_path)}"
            ),
            (
                "sudo -n python3 aegis-platform/scripts/production_host_deploy.py "
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
    parsed_origin = urlparse(origin)
    assert parsed_origin.hostname
    origin_port = parsed_origin.port or 443
    ssh_addresses = _resolved_enterprise_addresses(host, port, "SSH host")
    origin_addresses = _resolved_enterprise_addresses(parsed_origin.hostname, origin_port, "production origin")
    repo_path = _remote_path(repo_path, "remote repo path")
    env_path = _remote_path(env_path, "remote env path")
    _private_file(private_key, "SSH private key", 64 * 1024)
    _private_file(known_hosts, "SSH known-hosts", 1024 * 1024)
    _require_known_host(host, port, known_hosts)

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
        "deployment_mode": "internal",
        "host": host,
        "host_resolved_addresses": ssh_addresses,
        "port": port,
        "release_sha": release_sha,
        "origin": origin,
        "origin_resolved_addresses": origin_addresses,
        "network_scope": "rfc1918-or-ipv6-ula",
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
