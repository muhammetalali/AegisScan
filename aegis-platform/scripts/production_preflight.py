#!/usr/bin/env python3
"""Fail closed before AegisScan is started in a production environment."""
from __future__ import annotations

import argparse
import base64
import binascii
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_SECRETS = ("SECRET_KEY", "JWT_SECRET_KEY", "POSTGRES_PASSWORD", "CREDENTIAL_VAULT_KEYS", "CREDENTIAL_FINGERPRINT_KEY")
REQUIRED_URLS = ("DATABASE_URL", "REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND")
FORBIDDEN_SECRET_VALUES = {
    "change-me", "aegis", "password", "secret", "django-insecure-change-me",
    "replace-with-a-long-random-secret", "jwt-secret-change-me",
    "replace-with-a-separate-long-random-secret",
}
FORBIDDEN_SCAN_HOSTS = {"localhost", "metadata.google.internal", "aegis-scan-target"}
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
BACKUP_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
TRUTHY = {"1", "true", "yes", "on"}


def _items(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _check_credential_vault(environment: dict[str, str], failures: list[str]) -> None:
    raw_keys = [
        item.strip()
        for item in environment.get("CREDENTIAL_VAULT_KEYS", "").split(",")
        if item.strip()
    ]
    if not raw_keys:
        failures.append("CREDENTIAL_VAULT_KEYS must contain at least one Fernet-compatible key")
        return
    for raw in raw_keys:
        try:
            decoded = base64.urlsafe_b64decode(raw.encode("ascii"))
        except (UnicodeEncodeError, ValueError, binascii.Error):
            failures.append("CREDENTIAL_VAULT_KEYS contains invalid URL-safe base64")
            continue
        if len(decoded) != 32:
            failures.append("CREDENTIAL_VAULT_KEYS entries must decode to exactly 32 bytes")

    fingerprint = environment.get("CREDENTIAL_FINGERPRINT_KEY", "").strip()
    if len(fingerprint) < 32:
        failures.append("CREDENTIAL_FINGERPRINT_KEY must be at least 32 characters")
    if fingerprint in {
        environment.get("SECRET_KEY", ""),
        environment.get("JWT_SECRET_KEY", ""),
    }:
        failures.append("CREDENTIAL_FINGERPRINT_KEY must be distinct from application signing secrets")


def _is_forbidden_scan_target(value: str) -> bool:
    host = value.strip().lower().strip("[]")
    if host in FORBIDDEN_SCAN_HOSTS or host == "*":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast


def _is_unsafe_delivery_host(hostname: str) -> bool:
    host = hostname.strip().lower().strip("[]")
    if host in {"localhost", "metadata.google.internal"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast


def _check_alert_webhook(value: str, failures: list[str]) -> None:
    parsed = urlparse(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or _is_unsafe_delivery_host(parsed.hostname or "")
    ):
        failures.append(
            "ALERT_WEBHOOK_URL must be an explicit HTTPS destination without URL credentials, fragment, loopback or link-local host"
        )



def _truthy(value: str) -> bool:
    return value.strip().lower() in TRUTHY


def _check_private_backup_file(
    name: str,
    value: str,
    runtime_uid: int,
    failures: list[str],
    *,
    max_bytes: int,
) -> None:
    if not value.strip():
        failures.append(f"{name} must point to a private runtime file")
        return
    path = Path(value)
    if not path.is_file():
        failures.append(f"{name} must point to an existing file")
        return
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & 0o077:
        failures.append(f"{name} must not be readable or writable by group or others")
    if os.name == "posix" and info.st_uid != runtime_uid:
        failures.append(f"{name} must be owned by AEGIS_BACKUP_RUNTIME_UID")
    if info.st_size <= 0 or info.st_size > max_bytes:
        failures.append(f"{name} has an invalid size")


def _check_remote_backup(environment: dict[str, str], failures: list[str]) -> None:
    if not _truthy(environment.get("AEGIS_REMOTE_BACKUP_ENABLED", "")):
        failures.append("AEGIS_REMOTE_BACKUP_ENABLED must be explicitly true")
        return

    endpoint = environment.get("AEGIS_BACKUP_S3_ENDPOINT", "").strip()
    parsed = urlparse(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or _is_unsafe_delivery_host(parsed.hostname or "")
    ):
        failures.append(
            "AEGIS_BACKUP_S3_ENDPOINT must be an explicit HTTPS origin without URL "
            "credentials, query, fragment, loopback or link-local host"
        )

    bucket = environment.get("AEGIS_BACKUP_S3_BUCKET", "").strip()
    if (
        not BACKUP_BUCKET_RE.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
    ):
        failures.append("AEGIS_BACKUP_S3_BUCKET must be a valid explicit bucket name")

    prefix = environment.get("AEGIS_BACKUP_S3_PREFIX", "").strip().strip("/")
    if (
        not prefix
        or len(prefix) > 512
        or any(part in {"", ".", ".."} for part in prefix.split("/"))
        or "\\" in prefix
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in prefix)
    ):
        failures.append("AEGIS_BACKUP_S3_PREFIX must be an explicit safe object prefix")

    if environment.get("AEGIS_BACKUP_S3_ADDRESSING_STYLE", "path").strip() not in {
        "auto",
        "path",
        "virtual",
    }:
        failures.append("AEGIS_BACKUP_S3_ADDRESSING_STYLE must be auto, path or virtual")

    if not _truthy(environment.get("AEGIS_BACKUP_REQUIRE_VERSIONING", "")):
        failures.append("AEGIS_BACKUP_REQUIRE_VERSIONING must be explicitly true")

    try:
        interval = int(environment.get("AEGIS_BACKUP_INTERVAL_SECONDS", ""))
    except ValueError:
        interval = 0
    if interval < 3600:
        failures.append("AEGIS_BACKUP_INTERVAL_SECONDS must be at least 3600")

    try:
        runtime_uid = int(environment.get("AEGIS_BACKUP_RUNTIME_UID", "10001"))
        runtime_gid = int(environment.get("AEGIS_BACKUP_RUNTIME_GID", "10001"))
    except ValueError:
        runtime_uid = runtime_gid = 0
    if runtime_uid <= 0 or runtime_gid <= 0:
        failures.append("AEGIS_BACKUP_RUNTIME_UID and AEGIS_BACKUP_RUNTIME_GID must be non-root numeric IDs")
        runtime_uid = 10001

    _check_private_backup_file(
        "AEGIS_BACKUP_S3_CREDENTIALS_FILE",
        environment.get("AEGIS_BACKUP_S3_CREDENTIALS_FILE", ""),
        runtime_uid,
        failures,
        max_bytes=16 * 1024,
    )
    _check_private_backup_file(
        "AEGIS_BACKUP_ENCRYPTION_KEY_FILE",
        environment.get("AEGIS_BACKUP_ENCRYPTION_KEY_FILE", ""),
        runtime_uid,
        failures,
        max_bytes=256,
    )

    ca_bundle = environment.get("AEGIS_BACKUP_S3_CA_BUNDLE", "").strip()
    if ca_bundle and not Path(ca_bundle).is_file():
        failures.append("AEGIS_BACKUP_S3_CA_BUNDLE must point to an existing CA bundle")


def _check_certificate(cert: Path, key: Path, failures: list[str]) -> None:
    if not cert.is_file() or not key.is_file():
        failures.append("TLS fullchain.pem and privkey.pem must both exist")
        return
    if stat.S_IMODE(key.stat().st_mode) & 0o077:
        failures.append("TLS private key must not be readable by group or others")
    commands = (
        ["openssl", "x509", "-checkend", "604800", "-noout", "-in", str(cert)],
        ["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
        ["openssl", "pkey", "-in", str(key), "-pubout"],
    )
    try:
        expiry = subprocess.run(commands[0], capture_output=True, text=True, timeout=10)
        if expiry.returncode:
            failures.append("TLS certificate is invalid or expires within seven days")
        cert_key = subprocess.run(commands[1], capture_output=True, text=True, timeout=10)
        private_key = subprocess.run(commands[2], capture_output=True, text=True, timeout=10)
        if cert_key.returncode or private_key.returncode or cert_key.stdout != private_key.stdout:
            failures.append("TLS certificate and private key do not match")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        failures.append("OpenSSL is required for TLS production preflight")


def validate(environment: dict[str, str], tls_dir: Path, check_tls: bool = True) -> list[str]:
    failures: list[str] = []
    if environment.get("DEBUG", "").strip().lower() not in {"false", "0", "no", "off"}:
        failures.append("DEBUG must be explicitly false")
    for name in REQUIRED_SECRETS:
        value = environment.get(name, "").strip()
        if len(value) < 32 or value.lower() in FORBIDDEN_SECRET_VALUES:
            failures.append(f"{name} must be a non-default secret of at least 32 characters")
    if environment.get("SECRET_KEY") == environment.get("JWT_SECRET_KEY"):
        failures.append("SECRET_KEY and JWT_SECRET_KEY must be distinct")
    _check_credential_vault(environment, failures)
    for name in REQUIRED_URLS:
        parsed = urlparse(environment.get(name, ""))
        if not parsed.scheme or not parsed.hostname:
            failures.append(f"{name} must be an absolute service URL")
        elif parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            failures.append(f"{name} must not use a loopback host in production")
    allowed_hosts = _items(environment.get("ALLOWED_HOSTS", ""))
    if not allowed_hosts or any(host == "*" or not HOST_RE.fullmatch(host) for host in allowed_hosts):
        failures.append("ALLOWED_HOSTS must contain explicit valid hostnames and must not contain '*'")
    for name in ("CORS_ALLOWED_ORIGINS", "CSRF_TRUSTED_ORIGINS"):
        origins = _items(environment.get(name, ""))
        if not origins or any(urlparse(origin).scheme != "https" or not urlparse(origin).hostname for origin in origins):
            failures.append(f"{name} must contain explicit HTTPS origins")
    targets = _items(environment.get("AUTHORIZED_SCAN_TARGETS", ""))
    if not targets or any(_is_forbidden_scan_target(target) for target in targets):
        failures.append("AUTHORIZED_SCAN_TARGETS must be explicit and exclude wildcard, loopback, link-local and CI targets")
    _check_alert_webhook(environment.get("ALERT_WEBHOOK_URL", ""), failures)
    _check_remote_backup(environment, failures)
    if check_tls:
        _check_certificate(tls_dir / "fullchain.pem", tls_dir / "privkey.pem", failures)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tls-dir", type=Path, default=Path("docker/ssl"))
    parser.add_argument("--skip-tls", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    failures = validate(dict(os.environ), args.tls_dir, check_tls=not args.skip_tls)
    print(json.dumps({"policy": "aegisscan-production-preflight-v1", "ready": not failures, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
