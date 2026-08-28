from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ActiveScanResult:
    provider: str
    target: str
    observations: tuple[dict, ...]


class ScanAuthorizationError(ValueError):
    pass


class ActiveSurfaceScanner:
    """Executes installed network scanners only when explicitly enabled and scoped."""

    def __init__(self) -> None:
        self.enabled = os.getenv("AEGIS_ACTIVE_SCAN_ENABLED", "false").lower() == "true"
        self.timeout = int(os.getenv("AEGIS_ACTIVE_SCAN_TIMEOUT", "120"))
        self.allowed_networks = self._load_allowed_networks()

    @staticmethod
    def _load_allowed_networks() -> tuple[ipaddress._BaseNetwork, ...]:
        raw = os.getenv("AEGIS_ACTIVE_SCAN_CIDRS", "")
        networks: list[ipaddress._BaseNetwork] = []
        for value in raw.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise ScanAuthorizationError(f"Invalid configured CIDR: {value}") from exc
        return tuple(networks)

    def _authorize_target(self, target: str) -> None:
        if not self.enabled:
            raise ScanAuthorizationError("Active scanning is disabled by policy")
        if not self.allowed_networks:
            raise ScanAuthorizationError("No active-scan CIDR scope is configured")
        try:
            network = ipaddress.ip_network(target, strict=False)
            candidates = list(network.hosts()) if network.num_addresses <= 256 else [network.network_address]
        except ValueError:
            try:
                candidates = [ipaddress.ip_address(target)]
            except ValueError as exc:
                raise ScanAuthorizationError("Only IP addresses and CIDRs are allowed for active scans") from exc
        if not candidates or not all(any(candidate in allowed for allowed in self.allowed_networks) for candidate in candidates):
            raise ScanAuthorizationError("Target is outside the configured active-scan scope")

    async def scan(self, target: str, provider: Literal["nmap", "masscan"] = "nmap") -> ActiveScanResult:
        self._authorize_target(target)
        if shutil.which(provider) is None:
            raise RuntimeError(f"{provider} executable is not installed or not on PATH")
        if provider == "nmap":
            return await self._nmap(target)
        return await self._masscan(target)

    async def _run(self, args: list[str]) -> tuple[str, str]:
        process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("Active scanner timed out")
        if process.returncode != 0:
            raise RuntimeError(stderr.decode(errors="replace").strip() or "Active scanner failed")
        return stdout.decode(errors="replace"), stderr.decode(errors="replace")

    async def _nmap(self, target: str) -> ActiveScanResult:
        stdout, _ = await self._run(["nmap", "-Pn", "-sV", "-oX", "-", target])
        root = ET.fromstring(stdout)
        observations: list[dict] = []
        for host in root.findall("host"):
            address = host.find("address")
            asset = address.attrib.get("addr") if address is not None else target
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service = port.find("service")
                observations.append({
                    "asset": asset,
                    "port": int(port.attrib["portid"]),
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "service": service.attrib.get("name", "unknown") if service is not None else "unknown",
                    "version": service.attrib.get("version") if service is not None else None,
                    "source": "nmap",
                })
        return ActiveScanResult("nmap", target, tuple(observations))

    async def _masscan(self, target: str) -> ActiveScanResult:
        stdout, _ = await self._run(["masscan", target, "-p1-65535", "--rate", "1000", "--output-format", "json", "--output-filename", "-"])
        payload = stdout.strip()
        if not payload:
            return ActiveScanResult("masscan", target, ())
        try:
            rows = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Masscan returned invalid JSON") from exc
        observations = []
        for row in rows if isinstance(rows, list) else []:
            ip = row.get("ip", target)
            for item in row.get("ports", []):
                if item.get("status") != "open":
                    continue
                observations.append({
                    "asset": ip,
                    "port": int(item["port"]),
                    "protocol": item.get("proto", "tcp"),
                    "service": "unknown",
                    "version": None,
                    "source": "masscan",
                })
        return ActiveScanResult("masscan", target, tuple(observations))
