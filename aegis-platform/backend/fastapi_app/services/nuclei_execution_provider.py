from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi_app.services.kali_nuclei_provider import execute_kali_nuclei, nuclei_provider_decision
from fastapi_app.services.scanner_adapters import run_nuclei


@dataclass(frozen=True)
class NucleiExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


def run_nuclei_with_provider(
    *,
    target: str,
    timeout_seconds: int,
    routing_key: str,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
) -> NucleiExecutionResult:
    """Execute Nuclei through the authoritative governed provider decision.

    M5 admits legacy, canary, and parity-approved default-kali production
    modes. Raw kali remains provider-library diagnostic behavior and is
    rejected here. Any Kali execution is fail-closed and never falls back to
    the legacy scanner on provider, provenance, authorization, or runtime
    failure.
    """
    decision = nuclei_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary', 'default-kali'}:
        raise RuntimeError(
            f'Nuclei provider mode {decision.mode!r} is not admitted by the governed production execution layer'
        )
    routing = decision.as_dict()

    if decision.selected_provider == 'legacy':
        result = run_nuclei(
            target,
            timeout=timeout_seconds,
            state_getter=state_getter,
        )
        return NucleiExecutionResult(
            tool=result.tool,
            target=result.target,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            routing=routing,
            runtime={
                'provider': 'legacy-native-worker',
                'provenance_authority': 'production-scanner-adapter',
            },
        )

    if decision.selected_provider != 'kali':
        raise RuntimeError(f'Unsupported Nuclei provider decision: {decision.selected_provider!r}')

    result = execute_kali_nuclei(
        target=target,
        timeout_seconds=timeout_seconds,
        execution_ref=execution_ref,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        state_getter=state_getter,
    )
    return NucleiExecutionResult(
        tool=str(result['tool']),
        target=str(result['target']),
        exit_code=int(result['exit_code']),
        stdout=str(result['stdout']),
        stderr=str(result['stderr']),
        routing=routing,
        runtime=dict(result['runtime']),
    )
