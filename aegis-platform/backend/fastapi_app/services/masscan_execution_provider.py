from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi_app.services.kali_masscan_provider import (
    KaliMasscanProviderError,
    execute_kali_masscan,
    masscan_provider_decision,
)
from fastapi_app.services.scanner_adapters import run_masscan


_TRUTHY = {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True)
class MasscanExecutionResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str
    routing: dict[str, Any]
    runtime: dict[str, Any]


def legacy_masscan_disabled() -> bool:
    """Return whether this release has retired the local Masscan execution path."""
    return os.getenv('AEGIS_MASSCAN_LEGACY_DISABLED', '').strip().lower() in _TRUTHY


def _enforce_retirement_lock(decision: Any) -> None:
    """Fail closed when M6 production policy forbids same-release rollback."""
    if not legacy_masscan_disabled():
        return
    if decision.mode != 'default-kali' or decision.selected_provider != 'kali':
        raise KaliMasscanProviderError(
            'Legacy/Canary Masscan production routing is retired; rollback requires the previous release'
        )


def _deployment_option(value: str | None, env_name: str) -> str | None:
    if value is not None:
        normalized = str(value).strip()
        return normalized or None
    normalized = os.getenv(env_name, '').strip()
    return normalized or None


def run_masscan_with_provider(
    *,
    target: str,
    ports: str,
    rate: int,
    timeout_seconds: int,
    routing_key: str,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
    interface: str | None = None,
    adapter_ip: str | None = None,
    adapter_mac: str | None = None,
    router_mac: str | None = None,
) -> MasscanExecutionResult:
    """Execute Masscan through the authoritative governed provider decision.

    M6 production sets AEGIS_MASSCAN_LEGACY_DISABLED=true and admits only
    default-kali. Legacy and Canary remain reference-only when the retirement
    lock is absent. Any selected governed execution fails closed and is never
    silently retried through the local Masscan binary.
    """
    decision = masscan_provider_decision(routing_key=routing_key)
    if decision.mode not in {'legacy', 'canary', 'default-kali'}:
        raise RuntimeError(
            f'Masscan provider mode {decision.mode!r} is not admitted by the governed production execution layer'
        )
    _enforce_retirement_lock(decision)
    routing = decision.as_dict()
    options = {
        'interface': _deployment_option(interface, 'AEGIS_MASSCAN_INTERFACE'),
        'adapter_ip': _deployment_option(adapter_ip, 'AEGIS_MASSCAN_ADAPTER_IP'),
        'adapter_mac': _deployment_option(adapter_mac, 'AEGIS_MASSCAN_ADAPTER_MAC'),
        'router_mac': _deployment_option(router_mac, 'AEGIS_MASSCAN_ROUTER_MAC'),
    }

    if decision.selected_provider == 'legacy':
        result = run_masscan(
            target,
            ports=ports,
            rate=rate,
            timeout=timeout_seconds,
            state_getter=state_getter,
            **options,
        )
        return MasscanExecutionResult(
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
        raise RuntimeError(f'Unsupported Masscan provider decision: {decision.selected_provider!r}')

    result = execute_kali_masscan(
        target=target,
        ports=ports,
        rate=rate,
        timeout_seconds=timeout_seconds,
        execution_ref=execution_ref,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        state_getter=state_getter,
        **options,
    )
    return MasscanExecutionResult(
        tool=str(result['tool']),
        target=str(result['target']),
        exit_code=int(result['exit_code']),
        stdout=str(result['stdout']),
        stderr=str(result['stderr']),
        routing=routing,
        runtime=dict(result['runtime']),
    )
