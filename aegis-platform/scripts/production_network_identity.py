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



def selected_target_route(target: str) -> dict[str, Any]:
    """Describe the guest OS route to one requested IPv4, without probing it.

    When a Bridged NIC is attached, Linux chooses its connected subnet; under
    VMware NAT the default route may instead go through the NAT gateway. Neither
    result establishes that a target is reachable or authorized for scanning.
    """
    try:
        destination = ipaddress.IPv4Address(target.strip())
    except (ValueError, AttributeError) as exc:
        raise NetworkDiscoveryError("target route requires an IPv4 address") from exc
    if (
        destination.is_multicast
        or destination.is_unspecified
        or destination.is_loopback
        or destination.is_link_local
        or destination.is_reserved
    ):
        raise NetworkDiscoveryError("target is not a routable IPv4 host")
    routes = _ip_json("route", "get", str(destination))
    if len(routes) != 1:
        raise NetworkDiscoveryError("expected one unambiguous kernel route for target")
    entry = routes[0]
    name = entry.get("dev")
    if not isinstance(name, str) or not IFACE_RE.fullmatch(name):
        raise NetworkDiscoveryError("no valid route interface")
    if name.startswith(("docker", "br-", "veth", "virbr")):
        raise NetworkDiscoveryError("target resolves to a container-only bridge, not an office uplink")
    try:
        source = ipaddress.IPv4Address(str(entry["prefsrc"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise NetworkDiscoveryError("kernel route lacks a valid source IPv4") from exc
    via = entry.get("gateway")
    gateway = None
    if via is not None:
        try:
            gateway = str(ipaddress.IPv4Address(str(via)))
        except ValueError as exc:
            raise NetworkDiscoveryError("kernel route has invalid IPv4 gateway") from exc
    return {
        "schema": "aegisscan.target-route-context.v1",
        "target": str(destination),
        "interface": name,
        "source_ipv4": str(source),
        "gateway": gateway,
        "route_type": "via-gateway" if gateway else "on-link",
        "reachable": "not-proven-by-route",
        "scan_authorization": "not-inferred-from-connectivity",
    }


def windows_host_identity(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Normalize Windows physical-LAN network context, without granting scan rights."""
    if not isinstance(records, list):
        raise NetworkDiscoveryError("invalid Windows adapter inventory")
    available: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or record.get("up") is not True:
            continue
        name = record.get("name")
        description = str(record.get("description", "")).lower()
        if not isinstance(name, str) or not name.strip():
            continue
        if any(part in description for part in ("vmware", "virtual", "vpn", "hyper-v", "loopback", "tap-", "docker")):
            continue
        try:
            address = ipaddress.IPv4Interface(f'{record["ipv4"]}/{int(record["prefix"])}')
            index = int(record["index"])
        except (KeyError, ValueError, TypeError):
            continue
        if index < 1 or not _approved(address.ip):
            continue
        gateway_string = record.get("gateway")
        if gateway_string:
            try:
                gateway = ipaddress.IPv4Address(str(gateway_string))
            except ValueError:
                continue
            if gateway not in address.network or gateway == address.ip:
                continue
            gateway_string = str(gateway)
        available.append({
            "interface": name,
            "interface_index": index,
            "ipv4": str(address.ip),
            "subnet": str(address.network),
            "gateway": gateway_string or None,
            "origin": "windows-active-adapter",
        })
    available.sort(key=lambda x: (x["gateway"] is None, x["interface_index"], x["ipv4"]))
    return {
        "schema": "aegisscan.windows-host-lan.v1",
        "platform": "windows",
        "networks": available,
        "scan_authorization": "not-inferred-from-network-access",
    }


def discover_windows_host() -> dict[str, Any]:
    """Read native Windows interface information on whichever PC runs this."""
    if sys.platform != "win32":
        raise NetworkDiscoveryError("Windows host discovery must run on the Windows host")
    script = r"""
$ErrorActionPreference = 'Stop'
$records = @()
$physical = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
foreach ($adapter in $physical) {
  $idx = [int]$adapter.ifIndex
  $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $idx -ErrorAction SilentlyContinue |
      Where-Object { $_.AddressState -eq 'Preferred' })
  $routes = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
      Sort-Object RouteMetric)
  $gw = $null
  if ($routes.Count -gt 0) { $gw = [string]$routes[0].NextHop }
  foreach ($addr in $addresses) {
    $records += @{
      name = [string]$adapter.Name
      description = [string]$adapter.InterfaceDescription
      index = $idx
      up = $true
      ipv4 = [string]$addr.IPAddress
      prefix = [int]$addr.PrefixLength
      gateway = $gw
    }
  }
}
ConvertTo-Json -InputObject @($records) -Compress -Depth 4
"""
    try:
        process = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, check=True, timeout=25,
        )
        raw = json.loads(process.stdout.lstrip("\ufeff"))
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError) as exc:
        raise NetworkDiscoveryError("failed to read Windows active LAN adapters") from exc
    if isinstance(raw, dict):
        raw = [raw]
    return windows_host_identity(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="approved override for a multi-homed host")
    parser.add_argument("--target-route", help="read-only route selection for one chosen IPv4; never runs scans")
    parser.add_argument("--windows-host", action="store_true", help="detect active physical host LAN on Windows")
    parser.add_argument("--format", choices=("json", "tsv"), default="json")
    args = parser.parse_args()
    try:
        identity = (discover_windows_host() if args.windows_host or (sys.platform == "win32" and not args.target_route) else selected_target_route(args.target_route) if args.target_route else current_identity(args.interface))
    except NetworkDiscoveryError as exc:
        print(f"AEGIS_NETWORK_DISCOVERY_FAILED: {exc}", file=sys.stderr)
        return 1
    if (args.target_route or args.windows_host or sys.platform == "win32") and args.format == "tsv":
        print("Target route selection supports JSON output only", file=sys.stderr)
        return 2
    if args.format == "tsv":
        print("\t".join(identity[key] for key in ("interface", "cidr", "ipv4", "gateway")))
    else:
        print(json.dumps(identity, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
