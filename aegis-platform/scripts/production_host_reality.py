#!/usr/bin/env python3
"""Validate that a Linux host can run the complete AegisScan production execution plane."""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PLATFORM_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.backup.yml",
)
MIN_MEMORY_BYTES = 7 * 1024**3
MIN_DISK_BYTES = 60 * 1024**3


class HostValidationError(RuntimeError):
    pass


def _run(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if len(detail) > 4000:
            detail = detail[-4000:]
        suffix = f": {detail}" if detail else ""
        raise HostValidationError(
            f"command failed: {' '.join(argv)}: exit={exc.returncode}{suffix}"
        ) from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise HostValidationError(f"command failed: {' '.join(argv)}: {exc}") from exc


def _memory_bytes() -> int:
    with Path("/proc/meminfo").open(encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    raise HostValidationError("MemTotal missing from /proc/meminfo")


def _disk_free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _kernel_ipv4_forward() -> bool:
    path = Path("/proc/sys/net/ipv4/ip_forward")
    return path.is_file() and path.read_text(encoding="utf-8").strip() == "1"


def _require_commands() -> dict[str, str]:
    versions: dict[str, str] = {}
    commands = {
        "docker": ["docker", "--version"],
        "git": ["git", "--version"],
        "curl": ["curl", "--version"],
        "openssl": ["openssl", "version"],
    }
    for name, argv in commands.items():
        if shutil.which(name) is None:
            raise HostValidationError(f"required command is missing: {name}")
        result = _run(argv, timeout=30)
        versions[name] = (result.stdout or result.stderr).splitlines()[0].strip()
    compose = _run(["docker", "compose", "version"], timeout=30)
    versions["docker_compose"] = compose.stdout.strip()
    return versions


def _docker_info() -> dict[str, object]:
    info = json.loads(_run(["docker", "info", "--format", "{{json .}}"], timeout=60).stdout)
    if not info.get("ServerVersion"):
        raise HostValidationError("Docker daemon is not available")
    security_options = [str(item) for item in info.get("SecurityOptions", [])]
    return {
        "server_version": info.get("ServerVersion"),
        "driver": info.get("Driver"),
        "cgroup_driver": info.get("CgroupDriver"),
        "cgroup_version": info.get("CgroupVersion"),
        "security_options": security_options,
        "os_type": info.get("OSType"),
        "architecture": info.get("Architecture"),
    }


def _probe_capability(capability: str, command: str) -> None:
    _run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=missing",
            "--cap-drop=ALL",
            f"--cap-add={capability}",
            "alpine:3.20",
            "sh",
            "-ec",
            command,
        ],
        timeout=180,
    )


def _probe_shared_network_namespace() -> None:
    name = f"aegis-netns-probe-{os.getpid()}"
    try:
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--cap-drop=ALL",
                "alpine:3.20",
                "sh",
                "-c",
                "sleep 60",
            ],
            timeout=120,
        )
        _run(
            [
                "docker",
                "run",
                "--rm",
                f"--network=container:{name}",
                "alpine:3.20",
                "sh",
                "-ec",
                "test -d /sys/class/net/lo && ip addr show lo >/dev/null",
            ],
            timeout=120,
        )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            text=True,
            timeout=30,
        )


def _validate_compose(env_file: Path) -> None:
    argv = ["docker", "compose", "--env-file", str(env_file)]
    for name in COMPOSE_FILES:
        argv.extend(["-f", str(PLATFORM_DIR / name)])
    argv.extend(["config", "--quiet"])
    _run(argv, timeout=120)


def validate(env_file: Path) -> dict[str, object]:
    if platform.system() != "Linux":
        raise HostValidationError("production host must run Linux")
    if platform.machine() not in {"x86_64", "amd64"}:
        raise HostValidationError("current production images require x86_64/amd64")
    if os.geteuid() != 0:
        raise HostValidationError("host validation must run as root to prove production capabilities")
    if not env_file.is_file():
        raise HostValidationError(f"production env file not found: {env_file}")

    memory = _memory_bytes()
    if memory < MIN_MEMORY_BYTES:
        raise HostValidationError(
            f"host memory is below the 7 GiB production minimum: {memory}"
        )
    disk = _disk_free_bytes(PLATFORM_DIR)
    if disk < MIN_DISK_BYTES:
        raise HostValidationError(
            f"host free disk is below the 60 GiB production minimum: {disk}"
        )
    if not _kernel_ipv4_forward():
        raise HostValidationError("net.ipv4.ip_forward must be enabled for scanner egress isolation")

    versions = _require_commands()
    docker = _docker_info()
    if docker["os_type"] != "linux":
        raise HostValidationError("Docker daemon must use Linux containers")
    if docker["architecture"] not in {"x86_64", "amd64"}:
        raise HostValidationError("Docker daemon architecture must be amd64")

    _probe_capability("NET_RAW", "ping -c 1 -W 1 127.0.0.1 >/dev/null")
    _probe_capability("NET_ADMIN", "ip link set lo up && ip link show lo >/dev/null")
    _probe_shared_network_namespace()
    _validate_compose(env_file)

    result = {
        "schema": "aegisscan.production-host-reality.v1",
        "status": "success",
        "host": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "memory_bytes": memory,
            "free_disk_bytes": disk,
            "ipv4_forward": True,
        },
        "runtime": {
            "versions": versions,
            "docker": docker,
            "net_raw": True,
            "net_admin": True,
            "shared_network_namespace": True,
            "compose_contract": True,
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(args.env_file.resolve())
    except HostValidationError as exc:
        print(
            json.dumps(
                {
                    "schema": "aegisscan.production-host-reality.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
