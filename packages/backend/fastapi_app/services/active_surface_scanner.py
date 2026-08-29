from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
from dataclasses import dataclass
from typing import Literal

from defusedxml import ElementTree as ET


@dataclass(frozen=True)
class ActiveScanResult:
    provider: str
    target: str
    observations: tuple[dict, ...]


class ScanAuthorizationError(ValueError):
    """Raised when an active-scan target or provider is invalid."""


class ActiveSurfaceScanner:
    """Run an installed network scanner for an explicitly supplied target."""

    def __init__(self) -> None:
        self.timeout = 120

    @staticmethod
    def is_provider_available(provider: str) -> bool:
        return provider in {"nmap", "masscan"} and shutil.which(provider) is not None

    @staticmethod
    def _validate_target(target: str) -> None:
        value = str(target or "").strip()
        if not value:
            raise ScanAuthorizationError("Active scan target is required")
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.version not in {4, 6}:
                raise ScanAuthorizationError("Only IPv4 and IPv6 targets are allowed")
            return
        except ValueError:
            try:
                address = ipaddress.ip_address(value)
                if address.version not in {4, 6}:
                    raise ScanAuthorizationError("Only IPv4 and IPv6 targets are allowed")
                return
            except ValueError as exc:
                raise ScanAuthorizationError("Only IP addresses and CIDRs are allowed for active scans") from exc

    async def scan(self, target: str, provider: Literal["nmap", "masscan"] = "nmap") -> ActiveScanResult:
        self._validate_target(target)
        if provider not in {"nmap", "masscan"}:
            raise ScanAuthorizationError("Unsupported active scan provider")
        if not self.is_provider_available(provider):
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
