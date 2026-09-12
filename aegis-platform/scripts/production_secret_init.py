#!/usr/bin/env python3
"""Create private AegisScan production runtime secret material from explicit external inputs."""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
from pathlib import Path
from urllib.parse import quote, urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
TRUTHY = {"1", "true", "yes", "on"}


class SecretInitError(RuntimeError):
    pass


def _private_source(path: Path, *, max_bytes: int) -> bytes:
    if not path.is_file():
        raise SecretInitError(f"required source file does not exist: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SecretInitError(f"source secret file must not be readable/writable by group or others: {path}")
    data = path.read_bytes()
    if not data or len(data) > max_bytes:
        raise SecretInitError(f"source secret file has invalid size: {path}")
    return data


def _validate_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise SecretInitError("domain must be an explicit public DNS hostname")
    return domain


def _validate_https_origin(value: str, name: str) -> str:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SecretInitError(f"{name} must be an explicit HTTPS URL without URL credentials or fragment")
    host = parsed.hostname.strip().lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    ):
        raise SecretInitError(f"{name} must not use loopback/link-local/unspecified/multicast addressing")
    return value.strip()


def _validate_targets(values: list[str]) -> list[str]:
    targets: list[str] = []
    for raw in values:
        for item in raw.split(","):
            target = item.strip()
            if not target:
                continue
            if target == "*":
                raise SecretInitError("authorized scan targets must never contain wildcard '*'")
            host = target.strip("[]").lower()
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and (
                address.is_loopback
                or address.is_link_local
                or address.is_unspecified
                or address.is_multicast
            ):
                raise SecretInitError(f"unsafe authorized scan target: {target}")
            targets.append(target)
    if not targets:
        raise SecretInitError("at least one explicit authorized scan target is required")
    return sorted(set(targets))


def _validate_bucket(value: str) -> str:
    bucket = value.strip()
    if (
        not BUCKET_RE.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        raise SecretInitError("backup bucket name is invalid")
    return bucket


def _write_private(path: Path, data: bytes, *, owner: tuple[int, int] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.partial-{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        if owner is not None:
            os.chown(path, owner[0], owner[1])
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _env_line(name: str, value: str) -> str:
    if any(ch in value for ch in "\r\n\x00"):
        raise SecretInitError(f"invalid control character in {name}")
    return f"{name}={value}"


def initialize(
    *,
    domain: str,
    authorized_targets: list[str],
    alert_webhook: str,
    backup_endpoint: str,
    backup_bucket: str,
    backup_region: str,
    s3_credentials_source: Path,
    output_env: Path,
    secrets_dir: Path,
) -> dict[str, str]:
    domain = _validate_domain(domain)
    targets = _validate_targets(authorized_targets)
    alert_webhook = _validate_https_origin(alert_webhook, "alert webhook")
    backup_endpoint = _validate_https_origin(backup_endpoint, "backup endpoint")
    backup_bucket = _validate_bucket(backup_bucket)
    backup_region = backup_region.strip()
    if not backup_region or len(backup_region) > 64 or any(ch.isspace() for ch in backup_region):
        raise SecretInitError("backup region is invalid")

    credentials = _private_source(s3_credentials_source, max_bytes=16 * 1024)
    try:
        payload = json.loads(credentials)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecretInitError("S3 credentials source must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise SecretInitError("S3 credentials source must contain a JSON object")
    if not str(payload.get("access_key_id", "")).strip() or not str(payload.get("secret_access_key", "")).strip():
        raise SecretInitError("S3 credentials source must contain access_key_id and secret_access_key")

    secrets_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(secrets_dir, 0o700)
    if os.geteuid() == 0:
        runtime_uid = runtime_gid = 10001
        os.chown(secrets_dir, runtime_uid, runtime_gid)
    else:
        runtime_uid = os.getuid()
        runtime_gid = os.getgid()
    target_credentials = secrets_dir / "s3-credentials.json"
    encryption_key = secrets_dir / "backup-encryption.key"
    _write_private(target_credentials, credentials, owner=(runtime_uid, runtime_gid))
    _write_private(encryption_key, secrets.token_bytes(32), owner=(runtime_uid, runtime_gid))

    django_secret = secrets.token_urlsafe(64)
    jwt_secret = secrets.token_urlsafe(64)
    credential_vault_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    credential_fingerprint_key = secrets.token_urlsafe(48)
    postgres_password = secrets.token_urlsafe(48)
    postgres_password_url = quote(postgres_password, safe="")

    env = {
        "DEBUG": "False",
        "SECRET_KEY": django_secret,
        "JWT_SECRET_KEY": jwt_secret,
        "CREDENTIAL_VAULT_KEYS": credential_vault_key,
        "CREDENTIAL_FINGERPRINT_KEY": credential_fingerprint_key,
        "POSTGRES_DB": "aegisdb",
        "POSTGRES_USER": "aegis",
        "POSTGRES_PASSWORD": postgres_password,
        "DATABASE_URL": f"postgresql://aegis:{postgres_password_url}@postgres:5432/aegisdb",
        "REDIS_URL": "redis://redis:6379/0",
        "CELERY_BROKER_URL": "redis://redis:6379/0",
        "CELERY_RESULT_BACKEND": "redis://redis:6379/1",
        "ALLOWED_HOSTS": domain,
        "CORS_ALLOWED_ORIGINS": f"https://{domain}",
        "CSRF_TRUSTED_ORIGINS": f"https://{domain}",
        "FRONTEND_URL": f"https://{domain}",
        "AUTH_COOKIE_SECURE": "True",
        "AUTHORIZED_SCAN_TARGETS": ",".join(targets),
        "ALERT_WEBHOOK_URL": alert_webhook,
        "PROMETHEUS_RETENTION": "15d",
        "AEGIS_REMOTE_BACKUP_ENABLED": "true",
        "AEGIS_BACKUP_S3_ENDPOINT": backup_endpoint.rstrip("/"),
        "AEGIS_BACKUP_S3_REGION": backup_region,
        "AEGIS_BACKUP_S3_BUCKET": backup_bucket,
        "AEGIS_BACKUP_S3_PREFIX": "aegisscan/postgres",
        "AEGIS_BACKUP_S3_ADDRESSING_STYLE": "path",
        "AEGIS_BACKUP_REQUIRE_VERSIONING": "true",
        "AEGIS_BACKUP_INTERVAL_SECONDS": "86400",
        "AEGIS_BACKUP_RETRY_SECONDS": "300",
        "AEGIS_BACKUP_DUMP_TIMEOUT_SECONDS": "7200",
        "AEGIS_BACKUP_UPLOAD_TIMEOUT_SECONDS": "7200",
        "AEGIS_BACKUP_RUNTIME_UID": str(runtime_uid),
        "AEGIS_BACKUP_RUNTIME_GID": str(runtime_gid),
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE": str(target_credentials),
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE": str(encryption_key),
    }
    lines = [
        "# Generated by AegisScan production_secret_init.py. Keep mode 0600.",
        *(_env_line(name, value) for name, value in sorted(env.items())),
        "",
    ]
    _write_private(output_env, "\n".join(lines).encode("utf-8"))

    return {
        "schema": "aegisscan.production-secret-init.v1",
        "status": "success",
        "domain": domain,
        "env_file": str(output_env),
        "s3_credentials_file": str(target_credentials),
        "backup_encryption_key_file": str(encryption_key),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--authorized-target", action="append", required=True, dest="authorized_targets")
    parser.add_argument("--alert-webhook", required=True)
    parser.add_argument("--backup-endpoint", required=True)
    parser.add_argument("--backup-bucket", required=True)
    parser.add_argument("--backup-region", default="us-east-1")
    parser.add_argument("--s3-credentials-source", type=Path, required=True)
    parser.add_argument("--output-env", type=Path, default=Path("/etc/aegisscan/production.env"))
    parser.add_argument("--secrets-dir", type=Path, default=Path("/etc/aegisscan/secrets"))
    args = parser.parse_args()

    try:
        result = initialize(
            domain=args.domain,
            authorized_targets=args.authorized_targets,
            alert_webhook=args.alert_webhook,
            backup_endpoint=args.backup_endpoint,
            backup_bucket=args.backup_bucket,
            backup_region=args.backup_region,
            s3_credentials_source=args.s3_credentials_source.resolve(),
            output_env=args.output_env.resolve(),
            secrets_dir=args.secrets_dir.resolve(),
        )
    except SecretInitError as exc:
        print(json.dumps({
            "schema": "aegisscan.production-secret-init.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
