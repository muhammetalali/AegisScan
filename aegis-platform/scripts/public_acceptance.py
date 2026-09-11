#!/usr/bin/env python3
"""Verify the externally reachable AegisScan production surface over verified HTTPS."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "x-content-type-options",
}
MAX_BODY = 1024 * 1024


class AcceptanceError(RuntimeError):
    pass


def _origin(value: str, allow_loopback_test: bool) -> str:
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
        raise AcceptanceError("origin must be an explicit HTTPS origin without credentials, path, query or fragment")
    host = parsed.hostname.strip().lower()
    if host == "metadata.google.internal":
        raise AcceptanceError("metadata endpoint is not a valid production origin")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or (address.is_loopback and not allow_loopback_test)
    ):
        raise AcceptanceError("origin must not use loopback, link-local, unspecified or multicast addressing")
    if host == "localhost" and not allow_loopback_test:
        raise AcceptanceError("localhost is not a valid production origin")
    port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    return f"https://{parsed.hostname}{port}"


def _tls_evidence(origin: str) -> dict[str, str]:
    parsed = urlparse(origin)
    host = parsed.hostname
    if not host:
        raise AcceptanceError("verified TLS origin hostname is missing")
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                certificate = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise AcceptanceError(f"verified TLS handshake failed: {exc}") from exc
    if not der or not certificate or not version or not cipher:
        raise AcceptanceError("verified TLS handshake did not expose certificate/session evidence")
    not_after = str(certificate.get("notAfter", "")).strip()
    if not not_after:
        raise AcceptanceError("verified TLS certificate is missing notAfter")
    return {
        "version": version,
        "cipher": str(cipher[0]),
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "not_after": not_after,
    }


def _request(origin: str, path: str) -> tuple[int, dict[str, str], bytes]:
    request = Request(
        origin + path,
        headers={
            "User-Agent": "AegisScan-Production-Acceptance/1.0",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
        },
        method="GET",
    )
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=15, context=context) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise AcceptanceError(f"response body exceeded {MAX_BODY} bytes: {path}")
            return (
                int(response.status),
                {key.lower(): value for key, value in response.headers.items()},
                body,
            )
    except HTTPError as exc:
        raise AcceptanceError(f"{path} returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        raise AcceptanceError(f"{path} HTTPS request failed: {exc}") from exc


def validate(origin: str, *, allow_loopback_test: bool = False) -> dict[str, object]:
    canonical = _origin(origin, allow_loopback_test)
    tls_evidence = _tls_evidence(canonical)
    health_status, health_headers, health_body = _request(canonical, "/health")
    ready_status, ready_headers, ready_body = _request(canonical, "/ready")
    root_status, root_headers, _ = _request(canonical, "/")

    for path, status in (("/health", health_status), ("/ready", ready_status), ("/", root_status)):
        if status != 200:
            raise AcceptanceError(f"{path} did not return HTTP 200")

    missing = sorted(REQUIRED_SECURITY_HEADERS - set(root_headers))
    if missing:
        raise AcceptanceError(f"gateway is missing required security headers: {missing}")

    hsts = root_headers.get("strict-transport-security", "").lower()
    if "max-age=" not in hsts:
        raise AcceptanceError("Strict-Transport-Security header is invalid")

    for path, body in (("/health", health_body), ("/ready", ready_body)):
        if not body.strip():
            raise AcceptanceError(f"{path} returned an empty body")
        try:
            json.loads(body)
        except json.JSONDecodeError:
            # Some deployments may expose a concise plaintext readiness response.
            if len(body.strip()) > 4096:
                raise AcceptanceError(f"{path} returned a non-JSON oversized readiness body")

    result = {
        "schema": "aegisscan.public-acceptance.v1",
        "status": "success",
        "origin": canonical,
        "checks": {
            "verified_https": True,
            "tls": tls_evidence,
            "health_200": True,
            "ready_200": True,
            "frontend_200": True,
            "security_headers": sorted(REQUIRED_SECURITY_HEADERS),
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--allow-loopback-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        result = validate(args.origin, allow_loopback_test=args.allow_loopback_test)
    except AcceptanceError as exc:
        print(json.dumps({
            "schema": "aegisscan.public-acceptance.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
