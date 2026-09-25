#!/usr/bin/env python3
"""Fail-closed post-deploy operational acceptance on the real internal production host."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid
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


def _run(
    argv: list[str],
    *,
    timeout: int = 60,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=PLATFORM_DIR,
            text=True,
            input=input_text,
            capture_output=True,
            check=True,
            timeout=timeout,
            env=env,
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


def _compose_environment(env: dict[str, str], *, extra_profiles: set[str] | None = None) -> dict[str, str]:
    resolved = dict(os.environ)
    resolved.update(env)
    profiles = {item.strip() for item in resolved.get("COMPOSE_PROFILES", "").split(",") if item.strip()}
    mode = resolved.get("AEGIS_RECON_PROVIDER", "default-kali").strip().lower()
    try:
        canary_bps = int(resolved.get("AEGIS_KALI_RECON_CANARY_BPS", "0").strip())
    except ValueError:
        canary_bps = 0
    if mode in {"default-kali", "kali"} or (mode == "canary" and canary_bps > 0):
        profiles.add("kali-recon")
    if extra_profiles:
        profiles.update(extra_profiles)
    if profiles:
        resolved["COMPOSE_PROFILES"] = ",".join(sorted(profiles))
    else:
        resolved.pop("COMPOSE_PROFILES", None)
    return resolved


def _append_csv(value: str, item: str) -> str:
    entries = [entry.strip() for entry in value.split(",") if entry.strip()]
    if item not in entries:
        entries.append(item)
    return ",".join(entries)


def _validation_target_ip() -> str:
    result = _run(
        ["docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}", "aegis-scan-target"],
        timeout=30,
    )
    addresses = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(addresses) != 1:
        raise OperationalAcceptanceError("production E2E target must have exactly one isolated container address")
    try:
        address = ipaddress.ip_address(addresses[0])
    except ValueError as exc:
        raise OperationalAcceptanceError("production E2E target returned an invalid container address") from exc
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise OperationalAcceptanceError("production E2E target must use an isolated private IPv4 container address")
    return str(address)


def _current_sha() -> str:
    return _run(["git", "-c", f"safe.directory={REPO_ROOT}", "rev-parse", "HEAD"], timeout=30).stdout.strip()


def _running_services(
    env_file: Path,
    *,
    environment: dict[str, str] | None = None,
) -> set[str]:
    result = _run(
        _compose(env_file, "ps", "--status", "running", "--services"),
        timeout=60,
        env=environment,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _wait_required_services(
    env_file: Path,
    *,
    timeout_seconds: int,
    poll_seconds: int,
    environment: dict[str, str] | None = None,
    required_services: set[str] | None = None,
) -> list[str]:
    required = required_services or REQUIRED_RUNNING_SERVICES
    deadline = time.monotonic() + timeout_seconds
    last: set[str] = set()
    while time.monotonic() < deadline:
        try:
            last = _running_services(env_file, environment=environment)
        except OperationalAcceptanceError:
            last = set()
        if required <= last:
            return sorted(last)
        time.sleep(poll_seconds)
    missing = sorted(required - last)
    raise OperationalAcceptanceError(f"required production services did not become running: {missing}")


def _container_environment(container: str) -> dict[str, str]:
    result = _run(
        ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container],
        timeout=30,
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _activate_e2e_scope(
    env_file: Path,
    env: dict[str, str],
    *,
    timeout_seconds: int,
    poll_seconds: int,
) -> tuple[str, dict[str, str], list[str]]:
    profile_env = _compose_environment(env, extra_profiles={"ci-only"})
    _run(
        _compose(env_file, "--profile", "ci-only", "up", "-d", "scan_target"),
        timeout=300,
        env=profile_env,
    )
    target_ip = _validation_target_ip()
    runtime_env = dict(profile_env)
    runtime_env["AUTHORIZED_SCAN_TARGETS"] = _append_csv(env.get("AUTHORIZED_SCAN_TARGETS", ""), target_ip)
    runtime_env["SCANNER_EGRESS_PRIVATE_TARGETS"] = _append_csv(
        env.get("SCANNER_EGRESS_PRIVATE_TARGETS", ""),
        target_ip,
    )
    _run(
        _compose(env_file, "--profile", "ci-only", "up", "-d"),
        timeout=900,
        env=runtime_env,
    )
    services = _wait_required_services(
        env_file,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        environment=runtime_env,
        required_services=REQUIRED_RUNNING_SERVICES | {"scan_target"},
    )
    fastapi_env = _container_environment("aegis-fastapi")
    egress_env = _container_environment("aegis-scanner-egress")
    if target_ip not in {
        item.strip()
        for item in fastapi_env.get("AUTHORIZED_SCAN_TARGETS", "").split(",")
        if item.strip()
    }:
        raise OperationalAcceptanceError("production E2E target was not bound to the API authorization scope")
    if target_ip not in {
        item.strip()
        for item in egress_env.get("SCANNER_EGRESS_PRIVATE_TARGETS", "").split(",")
        if item.strip()
    }:
        raise OperationalAcceptanceError("production E2E target was not bound to the scanner egress scope")
    return target_ip, runtime_env, services


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



def _provision_e2e_fixture(
    env_file: Path,
    release_sha: str,
    target: str,
    *,
    environment: dict[str, str],
) -> dict[str, str]:
    unique = uuid.uuid4().hex[:16]
    actor_email = f"release-e2e-{unique}@aegisscan.local"
    actor_password = f"Aegis-E2E-{unique}-!9-{secrets.token_urlsafe(24)}"
    approver_email = f"release-e2e-approver-{unique}@aegisscan.local"
    approver_password = f"Aegis-E2E-Approver-{unique}-!7-{secrets.token_urlsafe(24)}"

    bootstrap = f"""
import json
from django.db import transaction
from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit
from django_project.users.models import User, UserRole

actor_email = {actor_email!r}
actor_password = {actor_password!r}
approver_email = {approver_email!r}
approver_password = {approver_password!r}
release_sha = {release_sha!r}

with transaction.atomic():
    stale = User.objects.filter(
        email__startswith='release-e2e-',
        email__endswith='@aegisscan.local',
        is_active=True,
    )
    for stale_user in stale:
        old_role = stale_user.role
        stale_user.is_active = False
        stale_user.save(update_fields=['is_active'])
        append_audit(
            action=AuditLog.Action.USER_UPDATE,
            result=AuditLog.Result.SUCCESS,
            resource_type='User',
            resource_id=str(stale_user.id),
            resource_repr=stale_user.email,
            changes={'is_active': {'from': True, 'to': False}, 'role': old_role},
            metadata={
                'event': 'stale_release_e2e_identity_deactivated',
                'release_sha': release_sha,
            },
            ip_address='127.0.0.1',
            user_agent='production-operational-acceptance',
        )

    actor = User.objects.create_user(
        email=actor_email,
        password=actor_password,
        first_name='Release',
        last_name='E2E Actor',
        role=UserRole.SECURITY_MANAGER,
    )
    approver = User.objects.create_user(
        email=approver_email,
        password=approver_password,
        first_name='Release',
        last_name='E2E Approver',
        role=UserRole.VIEWER,
    )
    for user, purpose in ((actor, 'actor'), (approver, 'approver')):
        append_audit(
            action=AuditLog.Action.USER_CREATE,
            result=AuditLog.Result.SUCCESS,
            resource_type='User',
            resource_id=str(user.id),
            resource_repr=user.email,
            metadata={{
                'event': 'release_e2e_identity_created',
                'purpose': purpose,
                'release_sha': release_sha,
            }},
            ip_address='127.0.0.1',
            user_agent='production-operational-acceptance',
        )
print(json.dumps({{
    'actor_id': str(actor.id),
    'approver_id': str(approver.id),
}}, sort_keys=True))
"""
    result = _run(
        _compose(
            env_file,
            "exec",
            "-T",
            "django",
            "python",
            "manage.py",
            "shell",
        ),
        timeout=60,
        input_text=bootstrap,
        env=environment,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise OperationalAcceptanceError("production E2E identity bootstrap returned no result")
    try:
        identity = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise OperationalAcceptanceError("production E2E identity bootstrap returned invalid JSON") from exc
    if not identity.get("actor_id") or not identity.get("approver_id"):
        raise OperationalAcceptanceError("production E2E identity bootstrap did not return both identities")

    fixture = {
        "schema": "aegisscan.production-e2e-fixture.v1",
        "release_sha": release_sha,
        "actor_id": str(identity["actor_id"]),
        "actor_email": actor_email,
        "actor_password": actor_password,
        "approver_id": str(identity["approver_id"]),
        "approver_email": approver_email,
        "approver_password": approver_password,
        "target": target,
    }
    return fixture


def _persist_e2e_fixture_for_deploy_user(fixture: dict[str, str]) -> str:
    try:
        account = pwd.getpwnam("aegisdeploy")
    except KeyError as exc:
        raise OperationalAcceptanceError("trusted deployment account aegisdeploy does not exist") from exc

    directory = Path(account.pw_dir) / ".aegis-e2e"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(directory, account.pw_uid, account.pw_gid)
    os.chmod(directory, 0o700)

    for stale in directory.glob("e2e-fixture-*.json"):
        try:
            if stale.is_file() and not stale.is_symlink():
                stale.unlink()
        except OSError as exc:
            raise OperationalAcceptanceError("unable to remove stale production E2E fixture") from exc

    path = directory / f"e2e-fixture-{uuid.uuid4().hex}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, account.pw_uid, account.pw_gid)
            payload = (json.dumps(fixture, sort_keys=True) + "\n").encode("utf-8")
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise OperationalAcceptanceError("unable to persist private production E2E fixture") from exc

    info = path.stat()
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != account.pw_uid or info.st_size <= 0:
        raise OperationalAcceptanceError("private production E2E fixture ownership or mode is invalid")
    return str(path)


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
    target_ip, e2e_environment, services = _activate_e2e_scope(
        env_file,
        env,
        timeout_seconds=service_timeout_seconds,
        poll_seconds=poll_seconds,
    )
    e2e_fixture = _provision_e2e_fixture(
        env_file,
        release_sha,
        target_ip,
        environment=e2e_environment,
    )
    e2e_fixture_path = _persist_e2e_fixture_for_deploy_user(e2e_fixture)
    return {
        "schema": "aegisscan.production-operational-acceptance.v1",
        "status": "success",
        "deployment_mode": "internal",
        "release_sha": release_sha,
        "required_services": sorted(REQUIRED_RUNNING_SERVICES),
        "running_services": services,
        "alertmanager": alertmanager,
        "backup": backup,
        "e2e_fixture_path": e2e_fixture_path,
        "e2e_fixture_provisioned": True,
        "e2e_scope": {
            "profile": "ci-only",
            "target_isolated": True,
            "authorization_transient": True,
        },
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
