from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi_app.services.kali_nuclei_provider import (
    KaliNucleiProviderError,
    execute_kali_nuclei,
    nuclei_provider_decision,
)
from fastapi_app.services.scanner_adapters import run_nuclei


_TRUTHY = {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True)
class NucleiExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


def legacy_nuclei_disabled() -> bool:
    """Return whether this release has retired the local Nuclei execution path."""
    return os.getenv('AEGIS_NUCLEI_LEGACY_DISABLED', '').strip().lower() in _TRUTHY


def _enforce_retirement_lock(decision: Any) -> None:
    """Fail closed when M6 production policy forbids same-release rollback.

    Historical Legacy/Canary behavior remains available only to parity/reference
    environments where the retirement lock is absent. Production sets
    AEGIS_NUCLEI_LEGACY_DISABLED=true and admits exactly the parity-approved
    default-kali decision. Rollback is deployment of the previous release,
    never a hidden local-provider fallback inside the retired release.
    """
    if not legacy_nuclei_disabled():
        return
    if decision.mode != 'default-kali' or decision.selected_provider != 'kali':
        raise KaliNucleiProviderError(
            'Legacy/Canary Nuclei production routing is retired; rollback requires the previous release'
        )


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

    M6 production sets AEGIS_NUCLEI_LEGACY_DISABLED=true and therefore admits
    only default-kali. Legacy and Canary remain reference-only when that lock
    is absent so semantic-parity workflows can compare historical behavior
    without reintroducing a production fallback.

    Any selected Kali execution is fail-closed: provider, provenance,
    authorization, control, or runtime failures propagate and are never retried
    through a local Nuclei binary.
    """
    decision = nuclei_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary', 'default-kali'}:
        raise RuntimeError(
            f'Nuclei provider mode {decision.mode!r} is not admitted by the governed production execution layer'
        )
    _enforce_retirement_lock(decision)
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
