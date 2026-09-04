from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .scanner_adapters import ScanResult, run_masscan, run_nmap, run_nuclei, run_semgrep, validate_authorized_target, validate_authorized_web_target, validate_code_target


@dataclass(frozen=True)
class ToolRequest:
    target: str
    authorized: bool
    options: dict[str, Any] = field(default_factory=dict)


class SecurityTool(ABC):
    category: str = 'generic'
    name: str = 'generic'

    @abstractmethod
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        raise NotImplementedError

    def validate(self, request: ToolRequest) -> str:
        if request.authorized is not True:
            raise PermissionError('Execution blocked: target is not explicitly authorized')
        return validate_authorized_target(request.target)


class NetworkScanner(SecurityTool): category = 'network'
class WebScanner(SecurityTool): category = 'web'
class CodeScanner(SecurityTool): category = 'code'
class ADScanner(SecurityTool): category = 'active_directory'


class ExploitationFramework(SecurityTool):
    category = 'exploitation'


class NmapNetworkScanner(NetworkScanner):
    name = 'nmap'
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        return run_nmap(self.validate(request), timeout=timeout)


class MasscanNetworkScanner(NetworkScanner):
    name = 'masscan'
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        target = self.validate(request)
        return run_masscan(target, ports=str(request.options.get('ports', '1-65535')), rate=int(request.options.get('rate', 1000)), timeout=timeout)


class NucleiWebScanner(WebScanner):
    name = 'nuclei'
    def run(self, request: ToolRequest, timeout: int = 600) -> ScanResult:
        if request.authorized is not True: raise PermissionError('Execution blocked: target is not explicitly authorized')
        return run_nuclei(validate_authorized_web_target(request.target), timeout=timeout)


class SemgrepCodeScanner(CodeScanner):
    name = 'semgrep'
    def run(self, request: ToolRequest, timeout: int = 600) -> ScanResult:
        if request.authorized is not True: raise PermissionError('Execution blocked: target is not explicitly authorized')
        return run_semgrep(validate_code_target(request.target), timeout=timeout)


class UnsupportedADScanner(ADScanner):
    name = 'ad-provider-not-configured'
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        self.validate(request)
        raise RuntimeError('No real Active Directory scanner provider is configured')


class SafeExploitationAssessment(ExploitationFramework):
    name = 'safe-exploitation-assessment'
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        self.validate(request)
        raise RuntimeError('Exploit execution is disabled; use a dedicated approved validation provider')


TOOL_REGISTRY: dict[str, SecurityTool] = {
    'nmap': NmapNetworkScanner(),
    'masscan': MasscanNetworkScanner(),
    'nuclei': NucleiWebScanner(),
    'semgrep': SemgrepCodeScanner(),
    'ad': UnsupportedADScanner(),
    'exploitation': SafeExploitationAssessment(),
}


def get_tool(name: str) -> SecurityTool:
    try:
        return TOOL_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f'Unknown security tool: {name}') from exc
