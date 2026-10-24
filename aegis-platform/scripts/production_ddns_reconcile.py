#!/usr/bin/env python3
"""Reconcile the internal production hostname with the host's DHCP IPv4 address."""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

from production_network_identity import NetworkDiscoveryError, current_identity

# The FQDN is a stable *identity*, never a static network locator.
# Explicit interface/network overrides remain supported for legacy approved
# deployments, but the default is DHCP route discovery in the existing module.
INTERFACE = os.environ.get("AEGIS_DDNS_INTERFACE", "").strip() or None
DNS_SERVER = os.environ.get("AEGIS_DDNS_SERVER", "127.0.0.1")
APPROVED_NETWORK = os.environ.get("AEGIS_DDNS_NETWORK", "").strip() or None
FQDN = os.environ.get("AEGIS_DDNS_FQDN", "aegis-prod.aegis.internal.")
ZONE = os.environ.get("AEGIS_DDNS_ZONE", "aegis.internal.")
KEY_FILE = Path(os.environ.get("AEGIS_DDNS_KEY", "/etc/aegisscan/ddns.key"))
TTL = int(os.environ.get("AEGIS_DDNS_TTL", "60"))


class ReconcileError(RuntimeError):
    """Raised when reconciliation cannot prove a safe authoritative state."""


def run(
    argv: list[str],
    *,
    stdin: str | None = None,
    timeout: int = 15,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            input=stdin,
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
        else:
            detail = str(exc)
        raise ReconcileError(f"command failed: {' '.join(argv)}: {detail}") from exc


def discover_bound_dhcp_identity() -> tuple[str, ipaddress.IPv4Address, str]:
    """Reuse the authoritative DHCP route detector; never guess a new uplink.

    Interface and subnet are selected from current kernel DHCP routes. An
    explicitly configured historical ingress boundary remains an optional
    *constraint*, not a fallback topology or an authorization to scan.
    """
    try:
        identity = current_identity(INTERFACE)
    except NetworkDiscoveryError as exc:
        raise ReconcileError(f"active DHCP route cannot be proved: {exc}") from exc
    address = ipaddress.IPv4Address(identity["ipv4"])
    active_network = ipaddress.IPv4Network(identity["cidr"])
    if APPROVED_NETWORK:
        try:
            approved = ipaddress.IPv4Network(APPROVED_NETWORK, strict=True)
        except ValueError as exc:
            raise ReconcileError("invalid approved ingress network") from exc
        if not active_network.subnet_of(approved):
            raise ReconcileError("current DHCP subnet is outside approved ingress boundary")
    return identity["interface"], address, str(active_network)


def discover_dynamic_ipv4() -> ipaddress.IPv4Address:
    """Compatibility accessor used by existing DNS discovery callers."""
    return discover_bound_dhcp_identity()[1]


def authoritative_addresses() -> list[ipaddress.IPv4Address]:
    result = run(
        [
            "/usr/bin/dig",
            f"@{DNS_SERVER}",
            FQDN,
            "A",
            "+short",
            "+time=3",
            "+tries=1",
        ]
    )

    addresses: list[ipaddress.IPv4Address] = []

    for value in result.stdout.splitlines():
        value = value.strip()
        if not value:
            continue

        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ReconcileError(f"invalid authoritative A response: {value}") from exc

        if not isinstance(address, ipaddress.IPv4Address):
            raise ReconcileError(f"unexpected non-IPv4 A response: {value}")

        addresses.append(address)

    return addresses


def _validate_key_permissions() -> None:
    if not KEY_FILE.is_file():
        raise ReconcileError(f"TSIG key is missing: {KEY_FILE}")

    mode = KEY_FILE.stat().st_mode & 0o777
    if mode & 0o077:
        raise ReconcileError(f"TSIG key permissions are too broad: {oct(mode)}")


def signed_update(address: ipaddress.IPv4Address) -> None:
    _validate_key_permissions()

    payload = (
        f"server {DNS_SERVER}\n"
        f"zone {ZONE}\n"
        f"update delete {FQDN} A\n"
        f"update add {FQDN} {TTL} A {address}\n"
        "send\n"
    )

    run(["/usr/bin/nsupdate", "-k", str(KEY_FILE)], stdin=payload)


def reconcile() -> dict[str, object]:
    interface, actual, active_network = discover_bound_dhcp_identity()
    before = authoritative_addresses()

    if before == [actual]:
        return {
            "schema": "aegisscan.production-ddns-reconcile.v1",
            "status": "success",
            "action": "unchanged",
            "interface": interface,
            "network_observed": active_network,
            "address": str(actual),
            "fqdn": FQDN.rstrip("."),
            "dns_server": DNS_SERVER,
        }

    signed_update(actual)

    after = authoritative_addresses()
    if after != [actual]:
        raise ReconcileError(
            "authoritative verification failed after update: "
            f"expected {[str(actual)]}, got {[str(value) for value in after]}"
        )

    return {
        "schema": "aegisscan.production-ddns-reconcile.v1",
        "status": "success",
        "action": "updated",
        "interface": interface,
        "network_observed": active_network,
        "address": str(actual),
        "fqdn": FQDN.rstrip("."),
        "dns_server": DNS_SERVER,
        "previous": [str(value) for value in before],
    }


def main() -> int:
    try:
        result = reconcile()
    except ReconcileError as exc:
        print(
            json.dumps(
                {
                    "schema": "aegisscan.production-ddns-reconcile.v1",
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
