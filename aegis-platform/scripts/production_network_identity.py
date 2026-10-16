#!/usr/bin/env python3
"""Discover a trusted DHCP uplink without assuming interface, MAC, or subnet.

Read-only; the installer must validate this identity before creating firewall
rules or changing a production resolver. Multiple equal primary uplinks fail
closed rather than selecting an arbitrary corporate network.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from typing import Any

APPROVED_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class NetworkDiscoveryError(RuntimeError):
    """The active corporate DHCP uplink cannot be unambiguously identified."""


def _ip_json(*arguments: str) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(
            ["ip", "-j", "-4", *arguments],
            capture_output=True,
            check=True,
            text=True,
            timeout=10,
        )
        value = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
        raise NetworkDiscoveryError("failed to inspect active IPv4 network") from exc
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise NetworkDiscoveryError("unexpected iproute2 JSON structure")
    return value


def _approved(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in APPROVED_PRIVATE_NETWORKS)


def _primary_route(routes: list[dict[str, Any]], selected_interface: str | None) -> tuple[str, ipaddress.IPv4Address]:
    candidates: list[tuple[int, str, ipaddress.IPv4Address]] = []
    for route in routes:
        name = route.get("dev")
        if route.get("dst") != "default" or not isinstance(name, str) or not IFACE_RE.fullmatch(name):
            continue
        if selected_interface is not None and name != selected_interface:
            continue
        try:
            gateway = ipaddress.IPv4Address(str(route["gateway"]))
            metric = int(route.get("metric", 0))
        except (KeyError, ValueError, TypeError):
            continue
        if metric >= 0 and _approved(gateway):
            candidates.append((metric, name, gateway))
    candidates.sort(key=lambda route: route[0])
    if not candidates:
        raise NetworkDiscoveryError("no approved private IPv4 default gateway")
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        raise NetworkDiscoveryError("multiple equally preferred IPv4 default routes")
    _, interface, gateway = candidates[0]
    return interface, gateway


def discover(
    routes: list[dict[str, Any]],
    interface_rows: list[dict[str, Any]],
    *,
    selected_interface: str | None = None,
) -> dict[str, str]:
    """Return DHCP interface/subnet/gateway, rejecting unsafe ambiguity."""
    name, gateway = _primary_route(routes, selected_interface)
    matching = [row for row in interface_rows if row.get("ifname") == name]
    if len(matching) != 1:
        raise NetworkDiscoveryError("chosen uplink interface is missing or ambiguous")
    row = matching[0]
    if row.get("operstate") not in ("UP", "UNKNOWN"):
        raise NetworkDiscoveryError("chosen uplink interface is not up")
    details = []
    for address in row.get("addr_info", []):
        if not isinstance(address, dict):
            continue
        if address.get("family") != "inet" or address.get("scope") != "global":
            continue
        if address.get("dynamic") is not True:
            continue
        try:
            iface = ipaddress.IPv4Interface(
                f'{address["local"]}/{int(address["prefixlen"])}'
            )
        except (KeyError, ValueError, TypeError):
            raise NetworkDiscoveryError("invalid DHCP lease from iproute2")
        if _approved(iface.ip) and _approved(iface.network.network_address):
            details.append(iface)
    if len(details) != 1:
        raise NetworkDiscoveryError("expected exactly one approved dynamic IPv4 lease")
    lease = details[0]
    if gateway not in lease.network:
        raise NetworkDiscoveryError("DHCP gateway is outside the active interface subnet")
    if gateway == lease.ip:
        raise NetworkDiscoveryError("DHCP gateway equals the host address")
    return {
        "interface": name,
        "ipv4": str(lease.ip),
        "cidr": str(lease.network),
        "gateway": str(gateway),
        "address_family": "ipv4",
        "allocation": "dhcp",
    }


def current_identity(selected_interface: str | None = None) -> dict[str, str]:
    routes = _ip_json("route", "show", "default")
    # Enumerate addresses only on the elected primary uplink without relying on ens33.
    primary, _ = _primary_route(routes, selected_interface)
    rows = _ip_json("addr", "show", "dev", primary)
    return discover(routes, rows, selected_interface=primary)



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="approved override for a multi-homed host")
    parser.add_argument("--format", choices=("json", "tsv"), default="json")
    args = parser.parse_args()
    try:
        identity = current_identity(args.interface)
    except NetworkDiscoveryError as exc:
        print(f"AEGIS_NETWORK_DISCOVERY_FAILED: {exc}", file=sys.stderr)
        return 1
    if args.format == "tsv":
        print("\t".join(identity[key] for key in ("interface", "cidr", "ipv4", "gateway")))
    else:
        print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
