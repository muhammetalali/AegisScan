from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi_app.services.kali_masscan_provider import (
    KaliMasscanProviderError,
    masscan_provider_decision,
)
from fastapi_app.services.masscan_execution_provider import run_masscan_with_provider
from fastapi_app.services.masscan_semantic_parity import compare_masscan_semantics

ARTIFACTS = Path('/artifacts')
TARGET = '172.31.2.10'
COMMON = {
    'target': TARGET,
    'ports': '22,80',
    'rate': 1000,
    'timeout_seconds': 120,
    'authorization_ref': 'auth-m5',
    'scope_ref': 'project:m5:asset:masscan',
    'state_getter': lambda: 'running',
}


def _write(name: str, payload: object) -> None:
    (ARTIFACTS / name).write_text(
        json.dumps(payload, sort_keys=True, indent=2) + '\n',
        encoding='utf-8',
    )


def default_kali() -> None:
    decision = masscan_provider_decision(routing_key='ignored-in-default')
    assert decision.mode == 'default-kali', decision
    assert decision.selected_provider == 'kali', decision
    assert decision.parity_approved is True, decision
    assert decision.canary_bps == 0, decision
    assert decision.bucket is None, decision
    assert decision.routing_key_digest == '', decision
    assert decision.reason == 'default-kali-parity-approved', decision

    result = run_masscan_with_provider(
        routing_key='scan-default',
        execution_ref='masscan-m5-default',
        **COMMON,
    )
    assert result.routing['selected_provider'] == 'kali', result.routing
    assert result.exit_code == 0, result.stderr
    assert result.runtime['provider'] == 'aegis-kali-network-masscan', result.runtime
    assert result.runtime['linux_privilege']['allowed_capabilities'] == ['CAP_NET_RAW'], result.runtime
    (ARTIFACTS / 'default-kali.json').write_text(result.stdout, encoding='utf-8')
    _write('default-kali-result.json', {'routing': result.routing, 'runtime': result.runtime})


def legacy_reference() -> None:
    result = run_masscan_with_provider(
        routing_key='legacy-reference',
        execution_ref='masscan-m5-legacy-reference',
        **COMMON,
    )
    assert result.routing['mode'] == 'legacy', result.routing
    assert result.routing['selected_provider'] == 'legacy', result.routing
    assert result.exit_code == 0, result.stderr
    (ARTIFACTS / 'legacy-reference.json').write_text(result.stdout, encoding='utf-8')
    _write('legacy-reference-result.json', {'routing': result.routing, 'runtime': result.runtime})


def compare() -> None:
    result = compare_masscan_semantics(
        (ARTIFACTS / 'legacy-reference.json').read_text(encoding='utf-8'),
        (ARTIFACTS / 'default-kali.json').read_text(encoding='utf-8'),
    )
    expected = [
        {'ip': TARGET, 'protocol': 'tcp', 'port': 22},
        {'ip': TARGET, 'protocol': 'tcp', 'port': 80},
    ]
    assert result['equivalent'] is True, result
    assert result['legacy']['observations'] == expected, result
    assert result['candidate']['observations'] == expected, result
    _write('default-kali-semantic-parity.json', result)


def outage() -> None:
    from fastapi_app.services import masscan_execution_provider as provider

    provider.run_masscan = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError('silent legacy fallback attempted')
    )
    try:
        provider.run_masscan_with_provider(
            routing_key='outage-default',
            execution_ref='masscan-m5-outage',
            timeout_seconds=30,
            **{k: v for k, v in COMMON.items() if k != 'timeout_seconds'},
        )
    except KaliMasscanProviderError as exc:
        _write('default-kali-outage.json', {'fail_closed': True, 'error': str(exc)})
        return
    raise AssertionError('default-kali provider outage did not fail closed')


def explicit_rollback() -> None:
    result = run_masscan_with_provider(
        routing_key='explicit-rollback',
        execution_ref='masscan-m5-explicit-rollback',
        **COMMON,
    )
    assert result.routing['mode'] == 'legacy', result.routing
    assert result.routing['selected_provider'] == 'legacy', result.routing
    assert result.exit_code == 0, result.stderr
    _write('explicit-legacy-rollback.json', {'routing': result.routing, 'runtime': result.runtime})


MODES = {
    'default': default_kali,
    'legacy-reference': legacy_reference,
    'compare': compare,
    'outage': outage,
    'explicit-rollback': explicit_rollback,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        raise SystemExit(f'usage: {Path(sys.argv[0]).name} ' + '|'.join(MODES))
    MODES[sys.argv[1]]()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
