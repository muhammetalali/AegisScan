#!/usr/bin/env python3
"""Verify the internal-only AegisScan production surface over enterprise-trusted HTTPS.

The filename is retained as a migration boundary for existing automation. Production
acceptance itself is fail-closed: the origin must resolve only to RFC1918 IPv4 or
IPv6 ULA addresses and TLS must chain to an explicitly configured enterprise CA.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import sys
from pathlib import Path
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
MAX_CA_BUNDLE = 2 * 1024 * 1024
DEFAULT_ENTERPRISE_CA_BUNDLE = Path("/etc/aegisscan/enterprise-ca.pem")
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")


class AcceptanceError(RuntimeError):
    pass


def _url_host(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if isinstance(address, ipaddress.IPv6Address) else host


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
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise AcceptanceError("origin port is invalid") from exc
    port = f":{parsed_port}" if parsed_port and parsed_port != 443 else ""
    return f"https://{_url_host(host)}{port}"


def _is_enterprise_private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in RFC1918_NETWORKS)
    return address in IPV6_ULA


def _resolved_internal_addresses(origin: str, allow_loopback_test: bool = False) -> list[str]:
    parsed = urlparse(origin)
    host = parsed.hostname
    if not host:
        raise AcceptanceError("production origin hostname is missing")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise AcceptanceError("origin port is invalid") from exc

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
            raise AcceptanceError(f"internal production DNS resolution failed for {host}: {exc}") from exc
        addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for item in resolved:
            sockaddr = item[4]
            if not sockaddr:
                continue
            try:
                addresses.add(ipaddress.ip_address(sockaddr[0]))
            except ValueError as exc:
                raise AcceptanceError(f"resolver returned an invalid address for {host}: {sockaddr[0]!r}") from exc

    if not addresses:
        raise AcceptanceError(f"internal production DNS returned no addresses for {host}")

    invalid = sorted(
        str(address)
        for address in addresses
        if not (_is_enterprise_private(address) or (allow_loopback_test and address.is_loopback))
    )
    if invalid:
        raise AcceptanceError(
            "internal-only production origin resolved outside RFC1918/IPv6-ULA perimeter: "
            + ", ".join(invalid)
        )
    return sorted(str(address) for address in addresses)


def _configure_loopback_test_ca(*, allow_loopback_test: bool) -> None:
    """Bridge legacy CI SSL_CERT_FILE only inside the explicit loopback-test boundary."""
    if not allow_loopback_test or os.getenv("AEGIS_ENTERPRISE_CA_BUNDLE", "").strip():
        return
    raw = os.getenv("SSL_CERT_FILE", "").strip()
    if not raw:
        return
    path = Path(raw)
    if not path.is_absolute():
        raise AcceptanceError("loopback-test SSL_CERT_FILE must be an absolute path")
    os.environ["AEGIS_ENTERPRISE_CA_BUNDLE"] = str(path)


def _ca_bundle_path() -> Path:
    raw = os.getenv("AEGIS_ENTERPRISE_CA_BUNDLE", "").strip()
    path = Path(raw) if raw else DEFAULT_ENTERPRISE_CA_BUNDLE
    if not path.is_absolute():
        raise AcceptanceError("AEGIS_ENTERPRISE_CA_BUNDLE must be an absolute path")
    if not path.is_file():
        raise AcceptanceError(f"enterprise CA bundle does not exist: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_CA_BUNDLE:
        raise AcceptanceError("enterprise CA bundle has invalid size")
    return path


def _ca_bundle_evidence() -> tuple[Path, str]:
    path = _ca_bundle_path()
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _tls_context() -> ssl.SSLContext:
    path = _ca_bundle_path()
    try:
        context = ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as exc:
        raise AcceptanceError(f"enterprise CA bundle is not a valid TLS trust anchor: {exc}") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _tls_evidence(origin: str) -> dict[str, str]:
    parsed = urlparse(origin)
    host = parsed.hostname
    if not host:
        raise AcceptanceError("verified TLS origin hostname is missing")
    port = parsed.port or 443
    context = _tls_context()
    try:
        with socket.create_connection((host, port), timeout=15) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                certificate = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise AcceptanceError(f"enterprise-verified TLS handshake failed: {exc}") from exc
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
            "User-Agent": "AegisScan-Internal-Production-Acceptance/2.0",
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.1",
        },
        method="GET",
    )
    context = _tls_context()
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
        raise AcceptanceError(f"{path} enterprise HTTPS request failed: {exc}") from exc


def validate(origin: str, *, allow_loopback_test: bool = False) -> dict[str, object]:
    canonical = _origin(origin, allow_loopback_test)
    resolved_addresses = _resolved_internal_addresses(canonical, allow_loopback_test)
    ca_path, ca_before = _ca_bundle_evidence()
    tls_evidence = _tls_evidence(canonical)
    health_status, health_headers, health_body = _request(canonical, "/health")
    ready_status, ready_headers, ready_body = _request(canonical, "/ready")
    root_status, root_headers, _ = _request(canonical, "/")
    resolved_after = _resolved_internal_addresses(canonical, allow_loopback_test)
    _, ca_after = _ca_bundle_evidence()
    if ca_before != ca_after:
        raise AcceptanceError("enterprise CA bundle changed during production acceptance")

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
            if len(body.strip()) > 4096:
                raise AcceptanceError(f"{path} returned a non-JSON oversized readiness body")

    return {
        "schema": "aegisscan.internal-production-acceptance.v1",
        "status": "success",
        "deployment_mode": "internal",
        "network_scope": "rfc1918-or-ipv6-ula",
        "origin": canonical,
        "resolved_addresses": resolved_addresses,
        "resolved_addresses_after": resolved_after,
        "enterprise_ca": {
            "path": str(ca_path),
            "sha256": ca_before,
        },
        "checks": {
            "verified_https": True,
            "internal_only_resolution": True,
            "enterprise_ca_verified": True,
            "tls": tls_evidence,
            "health_200": True,
            "ready_200": True,
            "frontend_200": True,
            "security_headers": sorted(REQUIRED_SECURITY_HEADERS),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--allow-loopback-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        _configure_loopback_test_ca(allow_loopback_test=args.allow_loopback_test)
        result = validate(args.origin, allow_loopback_test=args.allow_loopback_test)
    except AcceptanceError as exc:
        print(json.dumps({
            "schema": "aegisscan.internal-production-acceptance.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
