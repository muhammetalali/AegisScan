from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from .scanner_adapters import ScanResult, run_nmap, validate_authorized_target


@dataclass(frozen=True)
class ToolRequest:
    target: str
    authorized: bool
    options: dict[str, Any] = field(default_factory=dict)


class SecurityTool(ABC):
    category: str = "generic"
    name: str = "generic"

    @abstractmethod
    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        raise NotImplementedError

    def validate(self, request: ToolRequest) -> str:
        if request.authorized is not True:
            raise PermissionError("Execution blocked: target is not explicitly authorized")
        return validate_authorized_target(request.target)


class NetworkScanner(SecurityTool):
    category = "network"


class WebScanner(SecurityTool):
    category = "web"


class ADScanner(SecurityTool):
    category = "active_directory"


class ExploitationFramework(SecurityTool):
    """Interface only: destructive exploitation is deliberately not executed here.

    A provider may implement safe, non-destructive validation of an authorized
    environment. Actual exploitation, credential theft, persistence, or post-
    exploitation actions are outside this execution layer.
    """

    category = "exploitation"


class NmapNetworkScanner(NetworkScanner):
    name = "nmap"

    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        target = self.validate(request)
        return run_nmap(target, timeout=timeout)


class UnsupportedSafeScanner(WebScanner):
    """Explicitly fails instead of pretending an unsupported provider ran."""

    name = "web-provider-not-configured"

    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        self.validate(request)
        raise RuntimeError("No real web scanner provider is configured")


class UnsupportedADScanner(ADScanner):
    name = "ad-provider-not-configured"

    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        self.validate(request)
        raise RuntimeError("No real Active Directory scanner provider is configured")


class SafeExploitationAssessment(ExploitationFramework):
    """Non-destructive attack-path assessment boundary.

    It intentionally refuses to execute exploit, post-exploitation, or
    persistence payloads. This keeps the platform useful for authorized
    validation without turning the worker into an unrestricted attack runner.
    """

    name = "safe-exploitation-assessment"

    def run(self, request: ToolRequest, timeout: int = 300) -> ScanResult:
        self.validate(request)
        raise RuntimeError(
            "Exploit execution is disabled; use a dedicated approved validation provider"
        )


TOOL_REGISTRY: dict[str, SecurityTool] = {
    "nmap": NmapNetworkScanner(),
    "web": UnsupportedSafeScanner(),
    "ad": UnsupportedADScanner(),
    "exploitation": SafeExploitationAssessment(),
}


def get_tool(name: str) -> SecurityTool:
    try:
        return TOOL_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"Unknown security tool: {name}") from exc
