#!/usr/bin/env python3
"""Fail closed before AegisScan is started in a production environment."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_SECRETS = ("SECRET_KEY", "JWT_SECRET_KEY", "POSTGRES_PASSWORD")
REQUIRED_URLS = ("DATABASE_URL", "REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND")
FORBIDDEN_SECRET_VALUES = {
    "change-me", "aegis", "password", "secret", "django-insecure-change-me",
    "replace-with-a-long-random-secret", "jwt-secret-change-me",
    "replace-with-a-separate-long-random-secret",
}
FORBIDDEN_SCAN_HOSTS = {"localhost", "metadata.google.internal", "aegis-scan-target"}
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def _items(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _is_forbidden_scan_target(value: str) -> bool:
    host = value.strip().lower().strip("[]")
    if host in FORBIDDEN_SCAN_HOSTS or host == "*":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast


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
