from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi_app.services.kali_nmap_provider import execute_kali_nmap, nmap_provider_decision
from fastapi_app.services.tool_abstraction import ToolRequest, get_tool


@dataclass(frozen=True)
class NmapExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


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

    The M5 production deployment selects ``default-kali``. Legacy remains an
    explicit administrative rollback mode until the separate retirement phase,
    and canary remains available for rollback diagnostics. A Kali-selected
    execution is always fail-closed: provider/provenance failures are propagated
    and are never retried through the legacy adapter in the same delivery.
    Raw ``kali`` mode is intentionally not admitted by this production-facing
    layer so callers cannot bypass the governed promotion policy.
    """
    decision = nmap_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary', 'default-kali'}:
        raise RuntimeError(f'Nmap provider mode {decision.mode!r} is not admitted by the governed production execution layer')
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
