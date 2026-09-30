#!/usr/bin/env python3
"""Validate that a Linux host can run the complete AegisScan internal production plane."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

PLATFORM_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.backup.yml",
)
MIN_MEMORY_BYTES = 7 * 1024**3
MIN_DISK_BYTES = 60 * 1024**3
MIN_CPU_COUNT = 4
ENTERPRISE_CA_BUNDLE = Path("/etc/aegisscan/enterprise-ca.pem")
MAX_CA_BUNDLE = 2 * 1024 * 1024
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
OPERATIONAL_REQUIRED_ENV = (
    "ALERT_WEBHOOK_URL",
    "AEGIS_BACKUP_S3_ENDPOINT",
    "AEGIS_BACKUP_S3_BUCKET",
    "AEGIS_BACKUP_S3_CREDENTIALS_FILE",
    "AEGIS_BACKUP_ENCRYPTION_KEY_FILE",
)


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


def _enterprise_ca_evidence(path: Path = ENTERPRISE_CA_BUNDLE) -> dict[str, str]:
    if not path.is_file():
        raise HostValidationError(f"enterprise CA bundle is missing: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CA_BUNDLE:
        raise HostValidationError("enterprise CA bundle has invalid size")
    try:
        context = ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as exc:
        raise HostValidationError(f"enterprise CA bundle is not a valid TLS trust anchor: {exc}") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


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


def _private_file(path: Path, label: str, max_bytes: int = 2 * 1024 * 1024) -> None:
    if not path.is_file():
        raise HostValidationError(f"{label} does not exist")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise HostValidationError(f"{label} must be mode 0600 or stricter")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise HostValidationError(f"{label} has invalid size")


def _load_env(path: Path) -> dict[str, str]:
    _private_file(path, "production environment file")
    values: dict[str, str] = {}
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise HostValidationError(f"invalid production env assignment at line {line_no}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not ENV_KEY_RE.fullmatch(key):
            raise HostValidationError(f"invalid production env key at line {line_no}")
        value = value.strip()
        if value and value[0] in {"'", '"'}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise HostValidationError(f"unterminated production env value at line {line_no}")
            value = value[1:-1]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise HostValidationError(f"control character in production env at line {line_no}")
        values[key] = value
    return values


def _https_endpoint(value: str, label: str) -> None:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise HostValidationError(f"{label} must be an HTTPS endpoint without credentials or fragment")


def _validate_operational_material(env_file: Path) -> dict[str, bool]:
    env = _load_env(env_file)
    missing = [name for name in OPERATIONAL_REQUIRED_ENV if not env.get(name, "").strip()]
    if missing:
        raise HostValidationError("missing operational production material: " + ", ".join(missing))
    _https_endpoint(env["ALERT_WEBHOOK_URL"], "Alertmanager webhook")
    _https_endpoint(env["AEGIS_BACKUP_S3_ENDPOINT"], "backup endpoint")
    if env.get("AEGIS_ALLOW_HTTP_ALERT_WEBHOOK", "false").strip().lower() in {"1", "true", "yes", "on"}:
        raise HostValidationError("HTTP Alertmanager test override must be disabled in production")
    if env.get("AEGIS_BACKUP_ALLOW_HTTP_TEST_ONLY", "false").strip().lower() in {"1", "true", "yes", "on"}:
        raise HostValidationError("HTTP backup test override must be disabled in production")
    _private_file(Path(env["AEGIS_BACKUP_S3_CREDENTIALS_FILE"]), "backup credentials file", 256 * 1024)
    _private_file(Path(env["AEGIS_BACKUP_ENCRYPTION_KEY_FILE"]), "backup encryption key", 4096)
    return {
        "alert_webhook_https": True,
        "backup_endpoint_https": True,
        "backup_credentials_private": True,
        "backup_encryption_key_private": True,
    }


def _validate_compose(env_file: Path) -> None:
    argv = ["docker", "compose", "--env-file", str(env_file)]
    for name in COMPOSE_FILES:
        argv.extend(["-f", str(PLATFORM_DIR / name)])
    argv.extend(["config", "--quiet"])
    _run(argv, timeout=120)


def validate(env_file: Path, *, defer_disk_capacity: bool = False) -> dict[str, object]:
    if platform.system() != "Linux":
        raise HostValidationError("production host must run Linux")
    if platform.machine() not in {"x86_64", "amd64"}:
        raise HostValidationError("current production images require x86_64/amd64")
    if os.geteuid() != 0:
        raise HostValidationError("host validation must run as root to prove production capabilities")
    if not env_file.is_file():
        raise HostValidationError(f"production env file not found: {env_file}")
    operational_material = _validate_operational_material(env_file)

    cpu_count = os.cpu_count() or 0
    if cpu_count < MIN_CPU_COUNT:
        raise HostValidationError(
            f"host CPU count is below the {MIN_CPU_COUNT} vCPU production minimum: {cpu_count}"
        )

    memory = _memory_bytes()
    if memory < MIN_MEMORY_BYTES:
        raise HostValidationError(f"host memory is below the 7 GiB production minimum: {memory}")
    disk = _disk_free_bytes(PLATFORM_DIR)
    disk_capacity_satisfied = disk >= MIN_DISK_BYTES
    if not disk_capacity_satisfied and not defer_disk_capacity:
        raise HostValidationError(f"host free disk is below the 60 GiB production minimum: {disk}")
    if not _kernel_ipv4_forward():
        raise HostValidationError("net.ipv4.ip_forward must be enabled for scanner egress isolation")

    enterprise_ca = _enterprise_ca_evidence()
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

    return {
        "schema": "aegisscan.production-host-reality.v1",
        "status": "success",
        "deployment_mode": "internal",
        "enterprise_ca": enterprise_ca,
        "host": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "cpu_count": cpu_count,
            "memory_bytes": memory,
            "free_disk_bytes": disk,
            "minimum_free_disk_bytes": MIN_DISK_BYTES,
            "disk_capacity_satisfied": disk_capacity_satisfied,
            "disk_capacity_deferred_to_privileged_reclaim": bool(
                defer_disk_capacity and not disk_capacity_satisfied
            ),
            "ipv4_forward": True,
        },
        "operational_material": operational_material,
        "runtime": {
            "versions": versions,
            "docker": docker,
            "net_raw": True,
            "net_admin": True,
            "shared_network_namespace": True,
            "compose_contract": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument(
        "--defer-disk-capacity",
        action="store_true",
        help=(
            "Defer only the disk-capacity floor to the root-owned privileged deploy "
            "reclaim gate; all other host reality checks remain mandatory."
        ),
    )
    args = parser.parse_args()
    try:
        result = validate(
            args.env_file.resolve(),
            defer_disk_capacity=args.defer_disk_capacity,
        )
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
