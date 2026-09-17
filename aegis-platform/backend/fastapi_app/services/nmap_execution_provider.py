from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi_app.services.kali_nmap_provider import (
    KaliNmapProviderError,
    execute_kali_nmap,
    nmap_provider_decision,
)
from fastapi_app.services.tool_abstraction import ToolRequest, get_tool


_TRUTHY = {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True)
class NmapExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


def legacy_nmap_disabled() -> bool:
    """Return whether this release has retired the local Nmap execution path."""
    return os.getenv('AEGIS_NMAP_LEGACY_DISABLED', '').strip().lower() in _TRUTHY


def _enforce_retirement_lock(decision: Any) -> None:
    """Fail closed when M6 production policy forbids same-release rollback.

    M6 keeps historical Legacy/Canary code available only to parity/reference
    environments. Production sets ``AEGIS_NMAP_LEGACY_DISABLED=true`` and then
    admits exactly the parity-approved ``default-kali`` decision. Rollback is a
    deployment of the previous release, never a hidden provider fallback inside
    the retired release.
    """
    if not legacy_nmap_disabled():
        return
    if decision.mode != 'default-kali' or decision.selected_provider != 'kali':
        raise KaliNmapProviderError(
            'Legacy/Canary Nmap production routing is retired; rollback requires the previous release'
        )


def run_nmap_with_provider(
    *,
    target: str,
    timeout_seconds: int,
    routing_key: str,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
) -> NmapExecutionResult:
    """Execute Nmap through the authoritative governed provider decision.

    M6 production sets ``AEGIS_NMAP_LEGACY_DISABLED=true`` and therefore admits
    only ``default-kali``. Legacy and Canary remain reference-only behavior when
    that retirement lock is absent so semantic-parity regression workflows can
    compare historical execution without reintroducing a production fallback.
    Any selected Kali execution is fail-closed: provider, provenance, auth, or
    runtime failures propagate and are never retried through a local Nmap binary.
    """
    decision = nmap_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary', 'default-kali'}:
        raise RuntimeError(
            f'Nmap provider mode {decision.mode!r} is not admitted by the governed production execution layer'
        )
    _enforce_retirement_lock(decision)
    routing = decision.as_dict()

    if decision.selected_provider == 'legacy':
        result = get_tool('nmap').run(
            ToolRequest(target=target, authorized=True),
            timeout=timeout_seconds,
            state_getter=state_getter,
        )
        return NmapExecutionResult(
            tool=result.tool,
            target=result.target,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            routing=routing,
            runtime={
                'provider': 'legacy-native-worker',
                'provenance_authority': 'production-tool-adapter',
            },
        )

    if decision.selected_provider != 'kali':
        raise RuntimeError(f'Unsupported Nmap provider decision: {decision.selected_provider!r}')

    result = execute_kali_nmap(
        target=target,
        timeout_seconds=timeout_seconds,
        execution_ref=execution_ref,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        state_getter=state_getter,
    )
    return NmapExecutionResult(
        tool=str(result['tool']),
        target=str(result['target']),
        exit_code=int(result['exit_code']),
        stdout=str(result['stdout']),
        stderr=str(result['stderr']),
        routing=routing,
        runtime=dict(result['runtime']),
    )
