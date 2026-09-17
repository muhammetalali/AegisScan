#!/usr/bin/env python3
"""Fail-closed post-deploy operational acceptance on the real internal production host."""
from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCRIPT_DIR = Path(__file__).resolve().parent
PLATFORM_DIR = SCRIPT_DIR.parent
REPO_ROOT = PLATFORM_DIR.parent
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.backup.yml",
)
REQUIRED_RUNNING_SERVICES = {
    "postgres",
    "redis",
    "django",
    "fastapi",
    "nginx",
    "prometheus",
    "alertmanager",
    "backup",
}


class OperationalAcceptanceError(RuntimeError):
    pass


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=PLATFORM_DIR,
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()[-3000:]
        raise OperationalAcceptanceError(f"command failed: {argv[0]} {detail}".strip()) from exc


def _private_file(path: Path, label: str, max_bytes: int = 2 * 1024 * 1024) -> None:
    if not path.is_file():
        raise OperationalAcceptanceError(f"{label} does not exist")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise OperationalAcceptanceError(f"{label} must be mode 0600 or stricter")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise OperationalAcceptanceError(f"{label} has invalid size")


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
            raise OperationalAcceptanceError(f"invalid production env assignment at line {line_no}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not ENV_KEY_RE.fullmatch(key):
            raise OperationalAcceptanceError(f"invalid production env key at line {line_no}")
        value = value.strip()
        if value and value[0] in {"'", '"'}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise OperationalAcceptanceError(f"unterminated production env value at line {line_no}")
            value = value[1:-1]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise OperationalAcceptanceError(f"control character in production env at line {line_no}")
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
        raise OperationalAcceptanceError(f"{label} must be an HTTPS endpoint without credentials or fragment")


def _validate_operational_material(env: dict[str, str]) -> None:
    required = (
        "ALERT_WEBHOOK_URL",
        "AEGIS_BACKUP_S3_ENDPOINT",
        "AEGIS_BACKUP_S3_BUCKET",
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE",
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE",
    )
    missing = [name for name in required if not env.get(name, "").strip()]
    if missing:
        raise OperationalAcceptanceError("missing operational production material: " + ", ".join(missing))
    _https_endpoint(env["ALERT_WEBHOOK_URL"], "Alertmanager webhook")
    _https_endpoint(env["AEGIS_BACKUP_S3_ENDPOINT"], "backup endpoint")
    if env.get("AEGIS_ALLOW_HTTP_ALERT_WEBHOOK", "false").strip().lower() in {"1", "true", "yes", "on"}:
        raise OperationalAcceptanceError("HTTP Alertmanager test override must be disabled in production")
    if env.get("AEGIS_BACKUP_ALLOW_HTTP_TEST_ONLY", "false").strip().lower() in {"1", "true", "yes", "on"}:
        raise OperationalAcceptanceError("HTTP backup test override must be disabled in production")
    _private_file(Path(env["AEGIS_BACKUP_S3_CREDENTIALS_FILE"]), "backup credentials file", 256 * 1024)
    _private_file(Path(env["AEGIS_BACKUP_ENCRYPTION_KEY_FILE"]), "backup encryption key", 4096)


def _compose(env_file: Path, *args: str) -> list[str]:
    argv = ["docker", "compose", "--env-file", str(env_file)]
    for name in COMPOSE_FILES:
        argv.extend(["-f", str(PLATFORM_DIR / name)])
    argv.extend(args)
    return argv


def _current_sha() -> str:
    return _run(["git", "-c", f"safe.directory={REPO_ROOT}", "rev-parse", "HEAD"], timeout=30).stdout.strip()


def _running_services(env_file: Path) -> set[str]:
    result = _run(_compose(env_file, "ps", "--status", "running", "--services"), timeout=60)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _wait_required_services(env_file: Path, *, timeout_seconds: int, poll_seconds: int) -> list[str]:
    deadline = time.monotonic() + timeout_seconds
    last: set[str] = set()
    while time.monotonic() < deadline:
        try:
            last = _running_services(env_file)
        except OperationalAcceptanceError:
            last = set()
        if REQUIRED_RUNNING_SERVICES <= last:
            return sorted(last)
        time.sleep(poll_seconds)
    missing = sorted(REQUIRED_RUNNING_SERVICES - last)
    raise OperationalAcceptanceError(f"required production services did not become running: {missing}")


def _wait_alertmanager(env_file: Path, *, timeout_seconds: int, poll_seconds: int) -> dict[str, object]:
    probe = (
        "import urllib.request; "
        "r=urllib.request.urlopen('http://127.0.0.1:9093/-/ready', timeout=3); "
        "assert r.status == 200; print('ready')"
    )
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            result = _run(_compose(env_file, "exec", "-T", "alertmanager", "python", "-c", probe), timeout=15)
            if result.stdout.strip().endswith("ready"):
                return {"status": "ready"}
        except OperationalAcceptanceError as exc:
            last_error = str(exc)
        time.sleep(poll_seconds)
    raise OperationalAcceptanceError(f"Alertmanager did not become ready: {last_error[-1000:]}")


def _wait_backup(env_file: Path, *, timeout_seconds: int, poll_seconds: int) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            result = _run(
                _compose(
                    env_file,
                    "exec",
                    "-T",
                    "backup",
                    "python",
                    "/app/scripts/remote_backup_service.py",
                    "health",
                ),
                timeout=30,
            )
            lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if not lines:
                raise OperationalAcceptanceError("backup health returned no JSON")
            payload = json.loads(lines[-1])
            if payload.get("status") != "healthy" or not payload.get("backup_id"):
                raise OperationalAcceptanceError("backup health did not prove a committed remote backup")
            age = int(payload.get("age_seconds", -1))
            if age < 0:
                raise OperationalAcceptanceError("backup health returned invalid age")
            return {"status": "healthy", "backup_id": str(payload["backup_id"]), "age_seconds": age}
        except (OperationalAcceptanceError, json.JSONDecodeError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(poll_seconds)
    raise OperationalAcceptanceError(f"remote encrypted backup did not become healthy: {last_error[-1000:]}")


def accept(
    *,
    env_file: Path,
    release_sha: str,
    service_timeout_seconds: int = 300,
    backup_timeout_seconds: int = 1800,
    poll_seconds: int = 5,
) -> dict[str, object]:
    if not SHA_RE.fullmatch(release_sha):
        raise OperationalAcceptanceError("release SHA must be exactly 40 lowercase hexadecimal characters")
    env_file = env_file.resolve()
    env = _load_env(env_file)
    _validate_operational_material(env)
    if _current_sha() != release_sha:
        raise OperationalAcceptanceError("production host checkout does not match the accepted release SHA")
    _run(_compose(env_file, "config", "--quiet"), timeout=120)
    _run(["docker", "info"], timeout=60)
    services = _wait_required_services(env_file, timeout_seconds=service_timeout_seconds, poll_seconds=poll_seconds)
    alertmanager = _wait_alertmanager(env_file, timeout_seconds=service_timeout_seconds, poll_seconds=poll_seconds)
    backup = _wait_backup(env_file, timeout_seconds=backup_timeout_seconds, poll_seconds=poll_seconds)
    return {
        "schema": "aegisscan.production-operational-acceptance.v1",
        "status": "success",
        "deployment_mode": "internal",
        "release_sha": release_sha,
        "required_services": sorted(REQUIRED_RUNNING_SERVICES),
        "running_services": services,
        "alertmanager": alertmanager,
        "backup": backup,
        "operational_material": {
            "alert_webhook_https": True,
            "backup_endpoint_https": True,
            "backup_credentials_private": True,
            "backup_encryption_key_private": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=Path("/etc/aegisscan/production.env"))
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--service-timeout-seconds", type=int, default=300)
    parser.add_argument("--backup-timeout-seconds", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=int, default=5)
    args = parser.parse_args()
    if not 30 <= args.service_timeout_seconds <= 1800:
        print("service timeout must be between 30 and 1800 seconds", file=sys.stderr)
        return 2
    if not 60 <= args.backup_timeout_seconds <= 7200:
        print("backup timeout must be between 60 and 7200 seconds", file=sys.stderr)
        return 2
    if not 1 <= args.poll_seconds <= 30:
        print("poll interval must be between 1 and 30 seconds", file=sys.stderr)
        return 2
    try:
        result = accept(
            env_file=args.env_file,
            release_sha=args.release_sha,
            service_timeout_seconds=args.service_timeout_seconds,
            backup_timeout_seconds=args.backup_timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
    except OperationalAcceptanceError as exc:
        print(json.dumps({
            "schema": "aegisscan.production-operational-acceptance.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
