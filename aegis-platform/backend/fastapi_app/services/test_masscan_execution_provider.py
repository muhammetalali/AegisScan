from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import masscan_execution_provider as provider
from fastapi_app.services.kali_masscan_provider import (
    KaliMasscanProviderError,
    masscan_provider_decision,
)


def _kwargs(routing_key: str = 'scan-1') -> dict:
    return {
        'target': '192.0.2.0/24',
        'ports': '22,80',
        'rate': 1000,
        'timeout_seconds': 120,
        'routing_key': routing_key,
        'execution_ref': 'scan:scan-1:masscan',
        'authorization_ref': 'authorization-1',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _selected_key() -> str:
    return next(
        f'selected-{i}'
        for i in range(10000)
        if masscan_provider_decision(routing_key=f'selected-{i}').selected_provider == 'kali'
    )


def _legacy_result(**kwargs):
    assert kwargs['target'] == '192.0.2.0/24'
    assert kwargs['ports'] == '22,80'
    assert kwargs['rate'] == 1000
    assert kwargs['timeout'] == 120
    return SimpleNamespace(
        tool='masscan', target='192.0.2.0/24', exit_code=0,
        stdout='[]', stderr='',
    )


def _kali_result() -> dict:
    return {
        'tool': 'masscan', 'target': '192.0.2.0/24', 'exit_code': 0,
        'stdout': '[]', 'stderr': '',
        'runtime': {
            'provider': 'aegis-kali-network-masscan',
            'profile': 'network',
            'tool': 'masscan',
            'provenance_authority': 'control-plane-deployment-pins',
        },
    }


def test_library_default_remains_legacy(monkeypatch):
    monkeypatch.delenv('AEGIS_MASSCAN_PROVIDER', raising=False)
    monkeypatch.setattr(provider, 'run_masscan', _legacy_result)
    monkeypatch.setattr(provider, 'execute_kali_masscan', lambda **kwargs: pytest.fail('Kali must not run'))
    result = provider.run_masscan_with_provider(**_kwargs())
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_canary_assignment_is_stable_and_has_selected_and_holdback(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '2500')
    selected = holdback = None
    for index in range(10000):
        key = f'masscan-canary-{index}'
        decision = masscan_provider_decision(routing_key=key)
        assert masscan_provider_decision(routing_key=key) == decision
        if decision.selected_provider == 'kali' and selected is None:
            selected = decision
        if decision.selected_provider == 'legacy' and holdback is None:
            holdback = decision
        if selected and holdback:
            break
    assert selected is not None and selected.reason == 'canary-selected'
    assert holdback is not None and holdback.reason == 'canary-holdback'
    assert selected.canary_bps == holdback.canary_bps == 2500


def test_zero_bps_is_immediate_legacy_rollback(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '0')
    decision = masscan_provider_decision(routing_key='scan-1')
    assert decision.selected_provider == 'legacy'
    assert decision.reason == 'canary-rollback-zero'
    assert decision.bucket is None


def test_canary_rejects_rollout_above_twenty_five_percent(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '2501')
    with pytest.raises(KaliMasscanProviderError, match='0 to 2500'):
        masscan_provider_decision(routing_key='scan-1')


def test_selected_provider_failure_never_falls_back(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '2500')
    monkeypatch.setattr(provider, 'run_masscan', lambda **kwargs: pytest.fail('legacy fallback forbidden'))
    monkeypatch.setattr(
        provider, 'execute_kali_masscan',
        lambda **kwargs: (_ for _ in ()).throw(KaliMasscanProviderError('provider unavailable')),
    )
    with pytest.raises(KaliMasscanProviderError, match='provider unavailable'):
        provider.run_masscan_with_provider(**_kwargs(_selected_key()))


def test_selected_result_preserves_runtime_and_deployment_link_binding(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '2500')
    monkeypatch.setenv('AEGIS_MASSCAN_INTERFACE', 'eth0')
    monkeypatch.setenv('AEGIS_MASSCAN_ADAPTER_IP', '192.0.2.20')
    monkeypatch.setenv('AEGIS_MASSCAN_ADAPTER_MAC', '02:00:00:00:00:20')
    monkeypatch.setenv('AEGIS_MASSCAN_ROUTER_MAC', '02:00:00:00:00:01')
    captured = {}

    def execute(**kwargs):
        captured.update(kwargs)
        return _kali_result()

    monkeypatch.setattr(provider, 'execute_kali_masscan', execute)
    monkeypatch.setattr(provider, 'run_masscan', lambda **kwargs: pytest.fail('legacy must not run'))
    result = provider.run_masscan_with_provider(**_kwargs(_selected_key()))
    assert result.routing['selected_provider'] == 'kali'
    assert result.runtime['provider'] == 'aegis-kali-network-masscan'
    assert captured['interface'] == 'eth0'
    assert captured['adapter_ip'] == '192.0.2.20'
    assert captured['adapter_mac'] == '02:00:00:00:00:20'
    assert captured['router_mac'] == '02:00:00:00:00:01'


def test_raw_kali_mode_is_not_production_admitted(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'kali')
    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_masscan_with_provider(**_kwargs())
