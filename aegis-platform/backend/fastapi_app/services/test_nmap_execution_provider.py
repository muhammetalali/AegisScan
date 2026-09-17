from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import nmap_execution_provider as provider
from fastapi_app.services.kali_nmap_provider import KaliNmapProviderError, nmap_provider_decision


class _LegacyTool:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, request, *, timeout, state_getter):
        self.calls += 1
        assert request.target == '192.0.2.10'
        assert request.authorized is True
        assert timeout == 120
        assert state_getter() == 'running'
        return SimpleNamespace(
            tool='nmap', target='192.0.2.10', exit_code=0,
            stdout='<nmaprun/>', stderr='',
        )


def _kwargs(routing_key: str = 'scan-1') -> dict:
    return {
        'target': '192.0.2.10',
        'timeout_seconds': 120,
        'routing_key': routing_key,
        'execution_ref': 'scan:scan-1:nmap',
        'authorization_ref': 'authorization-1',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _selected_key() -> str:
    return next(
        f'selected-{i}'
        for i in range(10000)
        if nmap_provider_decision(routing_key=f'selected-{i}').selected_provider == 'kali'
    )


def _kali_result() -> dict:
    runtime = {
        'provider': 'aegis-kali-network',
        'profile': 'network',
        'tool': 'nmap',
        'provenance_authority': 'control-plane-deployment-pins',
    }
    return {
        'tool': 'nmap', 'target': '192.0.2.10', 'exit_code': 0,
        'stdout': '<nmaprun/>', 'stderr': '', 'runtime': runtime,
    }


def test_library_fallback_remains_legacy_without_deployment_policy(monkeypatch):
    monkeypatch.delenv('AEGIS_NMAP_PROVIDER', raising=False)
    monkeypatch.delenv('AEGIS_KALI_NMAP_CANARY_BPS', raising=False)
    tool = _LegacyTool()
    monkeypatch.setattr(provider, 'get_tool', lambda name: tool)
    monkeypatch.setattr(provider, 'execute_kali_nmap', lambda **kwargs: pytest.fail('Kali must not run without deployment policy'))

    result = provider.run_nmap_with_provider(**_kwargs())

    assert tool.calls == 1
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'
    assert result.runtime['provider'] == 'legacy-native-worker'
    assert result.stdout == '<nmaprun/>'


def test_default_kali_routes_without_canary_assignment(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '0')
    monkeypatch.setattr(provider, 'get_tool', lambda name: pytest.fail('legacy must not run under default-kali'))
    monkeypatch.setattr(provider, 'execute_kali_nmap', lambda **kwargs: _kali_result())

    first = provider.run_nmap_with_provider(**_kwargs('scan-a'))
    second = provider.run_nmap_with_provider(**_kwargs('scan-b'))

    for result in (first, second):
        assert result.routing['mode'] == 'default-kali'
        assert result.routing['selected_provider'] == 'kali'
        assert result.routing['parity_approved'] is True
        assert result.routing['canary_bps'] == 0
        assert result.routing['bucket'] is None
        assert result.routing['routing_key_digest'] == ''
        assert result.routing['reason'] == 'default-kali-parity-approved'
        assert result.runtime['provider'] == 'aegis-kali-network'


def test_default_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'default-kali')
    monkeypatch.setattr(provider, 'get_tool', lambda name: pytest.fail('legacy fallback is forbidden'))

    def _failed_kali(**kwargs):
        raise KaliNmapProviderError('provider unavailable')

    monkeypatch.setattr(provider, 'execute_kali_nmap', _failed_kali)
    with pytest.raises(KaliNmapProviderError, match='provider unavailable'):
        provider.run_nmap_with_provider(**_kwargs())


def test_explicit_legacy_mode_remains_administrative_rollback(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'legacy')
    tool = _LegacyTool()
    monkeypatch.setattr(provider, 'get_tool', lambda name: tool)
    monkeypatch.setattr(provider, 'execute_kali_nmap', lambda **kwargs: pytest.fail('Kali must not run during explicit rollback'))

    result = provider.run_nmap_with_provider(**_kwargs())

    assert tool.calls == 1
    assert result.routing['mode'] == 'legacy'
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'


def test_canary_assignment_is_stable_and_has_selected_and_holdback_cohorts(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '2500')
    selected = holdback = None
    for index in range(10000):
        key = f'nmap-canary-{index}'
        decision = nmap_provider_decision(routing_key=key)
        repeat = nmap_provider_decision(routing_key=key)
        assert repeat == decision
        if decision.selected_provider == 'kali' and selected is None:
            selected = decision
        if decision.selected_provider == 'legacy' and holdback is None:
            holdback = decision
        if selected and holdback:
            break
    assert selected is not None and selected.reason == 'canary-selected'
    assert holdback is not None and holdback.reason == 'canary-holdback'
    assert selected.canary_bps == holdback.canary_bps == 2500


def test_canary_zero_is_explicit_rollback_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '0')
    decision = nmap_provider_decision(routing_key='any-stable-scan-id')
    assert decision.selected_provider == 'legacy'
    assert decision.reason == 'canary-rollback-zero'
    assert decision.bucket is None


def test_canary_rejects_rollout_above_twenty_five_percent(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '2501')
    with pytest.raises(KaliNmapProviderError, match='0 to 2500'):
        nmap_provider_decision(routing_key='scan-1')


def test_selected_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '2500')
    selected_key = _selected_key()
    monkeypatch.setattr(provider, 'get_tool', lambda name: pytest.fail('legacy fallback is forbidden'))

    def _failed_kali(**kwargs):
        raise KaliNmapProviderError('runtime attestation mismatch')

    monkeypatch.setattr(provider, 'execute_kali_nmap', _failed_kali)
    with pytest.raises(KaliNmapProviderError, match='attestation mismatch'):
        provider.run_nmap_with_provider(**_kwargs(selected_key))


def test_selected_kali_result_preserves_runtime_provenance(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NMAP_CANARY_BPS', '2500')
    selected_key = _selected_key()
    monkeypatch.setattr(provider, 'get_tool', lambda name: pytest.fail('legacy must not run'))
    monkeypatch.setattr(provider, 'execute_kali_nmap', lambda **kwargs: _kali_result())
    result = provider.run_nmap_with_provider(**_kwargs(selected_key))
    assert result.routing['mode'] == 'canary'
    assert result.routing['selected_provider'] == 'kali'
    assert result.runtime == _kali_result()['runtime']


def test_raw_kali_mode_is_rejected_by_production_execution_layer(monkeypatch):
    monkeypatch.setenv('AEGIS_NMAP_PROVIDER', 'kali')
    monkeypatch.setattr(provider, 'get_tool', lambda name: pytest.fail('legacy must not run'))
    monkeypatch.setattr(provider, 'execute_kali_nmap', lambda **kwargs: pytest.fail('raw Kali mode must not run'))
    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_nmap_with_provider(**_kwargs())
