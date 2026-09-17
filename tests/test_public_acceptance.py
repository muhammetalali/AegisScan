import importlib.util
import ipaddress
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/public_acceptance.py"
SPEC = importlib.util.spec_from_file_location("public_acceptance", PATH)
assert SPEC and SPEC.loader
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def test_origin_requires_verified_https_and_rejects_loopback():
    assert acceptance._origin("https://security.internal", False) == "https://security.internal"
    assert acceptance._origin("https://10.24.8.20:8443", False) == "https://10.24.8.20:8443"
    with pytest.raises(acceptance.AcceptanceError):
        acceptance._origin("http://security.internal", False)
    with pytest.raises(acceptance.AcceptanceError):
        acceptance._origin("https://localhost", False)
    assert acceptance._origin("https://localhost:8443", True) == "https://localhost:8443"


def test_enterprise_private_policy_is_rfc1918_or_ipv6_ula_only():
    accepted = ("10.0.0.1", "172.16.1.2", "192.168.50.4", "fd12:3456::10")
    rejected = ("127.0.0.1", "169.254.1.1", "203.0.113.10", "8.8.8.8", "fe80::1", "2001:4860:4860::8888")
    for value in accepted:
        assert acceptance._is_enterprise_private(ipaddress.ip_address(value)) is True
    for value in rejected:
        assert acceptance._is_enterprise_private(ipaddress.ip_address(value)) is False


def test_internal_dns_must_resolve_exclusively_to_private_addresses(monkeypatch):
    monkeypatch.setattr(
        acceptance.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (acceptance.socket.AF_INET, acceptance.socket.SOCK_STREAM, 6, "", ("10.20.30.40", 443)),
            (acceptance.socket.AF_INET, acceptance.socket.SOCK_STREAM, 6, "", ("192.168.4.8", 443)),
        ],
    )
    assert acceptance._resolved_internal_addresses("https://security.internal") == ["10.20.30.40", "192.168.4.8"]

    monkeypatch.setattr(
        acceptance.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (acceptance.socket.AF_INET, acceptance.socket.SOCK_STREAM, 6, "", ("10.20.30.40", 443)),
            (acceptance.socket.AF_INET, acceptance.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        ],
    )
    with pytest.raises(acceptance.AcceptanceError, match="outside RFC1918/IPv6-ULA"):
        acceptance._resolved_internal_addresses("https://security.internal")


def test_enterprise_ca_bundle_is_required_and_absolute(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("AEGIS_ENTERPRISE_CA_BUNDLE", "relative-ca.pem")
    with pytest.raises(acceptance.AcceptanceError, match="absolute path"):
        acceptance._ca_bundle_path()

    missing = tmp_path / "missing-ca.pem"
    monkeypatch.setenv("AEGIS_ENTERPRISE_CA_BUNDLE", str(missing))
    with pytest.raises(acceptance.AcceptanceError, match="does not exist"):
        acceptance._ca_bundle_path()


def test_validate_requires_health_ready_frontend_headers_and_internal_ca_evidence(monkeypatch):
    headers = {name: "present" for name in acceptance.REQUIRED_SECURITY_HEADERS}
    headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"

    monkeypatch.setattr(acceptance, "_resolved_internal_addresses", lambda *args, **kwargs: ["10.20.30.40"])
    monkeypatch.setattr(acceptance, "_ca_bundle_evidence", lambda: (Path("/etc/aegisscan/enterprise-ca.pem"), "c" * 64))
    monkeypatch.setattr(
        acceptance,
        "_request",
        lambda origin, path: (
            200,
            headers,
            b'{"status":"ok"}' if path in {"/health", "/ready"} else b"<html></html>",
        ),
    )
    monkeypatch.setattr(
        acceptance,
        "_tls_evidence",
        lambda origin: {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": "a" * 64,
            "not_after": "Dec 31 23:59:59 2026 GMT",
        },
    )

    result = acceptance.validate("https://security.internal")
    assert result["status"] == "success"
    assert result["deployment_mode"] == "internal"
    assert result["network_scope"] == "rfc1918-or-ipv6-ula"
    assert result["resolved_addresses"] == ["10.20.30.40"]
    assert result["enterprise_ca"]["sha256"] == "c" * 64
    assert result["checks"]["verified_https"] is True
    assert result["checks"]["internal_only_resolution"] is True
    assert result["checks"]["enterprise_ca_verified"] is True


def test_validate_rejects_ca_rotation_during_acceptance(monkeypatch):
    headers = {name: "present" for name in acceptance.REQUIRED_SECURITY_HEADERS}
    headers["strict-transport-security"] = "max-age=31536000"
    digests = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(acceptance, "_resolved_internal_addresses", lambda *args, **kwargs: ["10.20.30.40"])
    monkeypatch.setattr(
        acceptance,
        "_ca_bundle_evidence",
        lambda: (Path("/etc/aegisscan/enterprise-ca.pem"), next(digests)),
    )
    monkeypatch.setattr(
        acceptance,
        "_tls_evidence",
        lambda origin: {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_sha256": "d" * 64,
            "not_after": "Dec 31 23:59:59 2026 GMT",
        },
    )
    monkeypatch.setattr(acceptance, "_request", lambda *args: (200, headers, b'{"status":"ok"}'))
    with pytest.raises(acceptance.AcceptanceError, match="changed during production acceptance"):
        acceptance.validate("https://security.internal")
