from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import nuclei_execution_provider as provider
from fastapi_app.services.kali_nuclei_provider import (
    KaliNucleiProviderError,
    nuclei_provider_decision,
)


class _LegacyNuclei:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, target, *, timeout, state_getter):
        self.calls += 1
        assert target == 'http://192.0.2.20'
        assert timeout == 120
        assert state_getter() == 'running'
        return SimpleNamespace(
            tool='nuclei',
            target=target,
            exit_code=0,
            stdout='{"template-id":"fixture"}\n',
            stderr='',
        )


def _kwargs(routing_key: str = 'scan-1') -> dict:
    return {
        'target': 'http://192.0.2.20',
        'timeout_seconds': 120,
        'routing_key': routing_key,
        'execution_ref': 'scan:scan-1:nuclei',
        'authorization_ref': 'authorization-1',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _selected_key() -> str:
    return next(
        f'nuclei-canary-{i}'
        for i in range(10000)
        if nuclei_provider_decision(routing_key=f'nuclei-canary-{i}').selected_provider == 'kali'
    )


def _kali_result() -> dict:
    runtime = {
        'provider': 'aegis-kali-web',
        'profile': 'web',
        'tool': 'nuclei',
        'provenance_authority': 'control-plane-deployment-pins',
    }
    return {
        'tool': 'nuclei',
        'target': 'http://192.0.2.20',
        'exit_code': 0,
        'stdout': '{"template-id":"fixture"}\n',
        'stderr': '',
        'runtime': runtime,
    }


def test_library_fallback_remains_legacy_without_deployment_policy(monkeypatch):
    monkeypatch.delenv('AEGIS_NUCLEI_PROVIDER', raising=False)
    monkeypatch.delenv('AEGIS_KALI_NUCLEI_CANARY_BPS', raising=False)
    legacy = _LegacyNuclei()
    monkeypatch.setattr(provider, 'run_nuclei', legacy)
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('Kali must not run without deployment policy'),
    )

    result = provider.run_nuclei_with_provider(**_kwargs())

    assert legacy.calls == 1
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_default_kali_routes_without_canary_assignment(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '0')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('legacy must not run under default-kali'),
    )
    monkeypatch.setattr(provider, 'execute_kali_nuclei', lambda **kwargs: _kali_result())

    first = provider.run_nuclei_with_provider(**_kwargs('scan-a'))
    second = provider.run_nuclei_with_provider(**_kwargs('scan-b'))

    for result in (first, second):
        assert result.routing['mode'] == 'default-kali'
        assert result.routing['selected_provider'] == 'kali'
        assert result.routing['parity_approved'] is True
        assert result.routing['canary_bps'] == 0
        assert result.routing['bucket'] is None
        assert result.routing['routing_key_digest'] == ''
        assert result.routing['reason'] == 'default-kali-parity-approved'
        assert result.runtime['provider'] == 'aegis-kali-web'


def test_default_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'default-kali')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('legacy fallback is forbidden'),
    )

    def _failed_kali(**kwargs):
        raise KaliNucleiProviderError('provider unavailable')

    monkeypatch.setattr(provider, 'execute_kali_nuclei', _failed_kali)
    with pytest.raises(KaliNucleiProviderError, match='provider unavailable'):
        provider.run_nuclei_with_provider(**_kwargs())


def test_explicit_legacy_mode_remains_administrative_rollback(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'legacy')
    legacy = _LegacyNuclei()
    monkeypatch.setattr(provider, 'run_nuclei', legacy)
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('Kali must not run during explicit rollback'),
    )

    result = provider.run_nuclei_with_provider(**_kwargs())

    assert legacy.calls == 1
    assert result.routing['mode'] == 'legacy'
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'


def test_canary_assignment_is_stable_and_has_selected_and_holdback_cohorts(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '2500')
    selected = holdback = None
    for index in range(10000):
        key = f'nuclei-canary-{index}'
        decision = nuclei_provider_decision(routing_key=key)
        assert nuclei_provider_decision(routing_key=key) == decision
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
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '0')
    decision = nuclei_provider_decision(routing_key='any-stable-scan-id')
    assert decision.selected_provider == 'legacy'
    assert decision.reason == 'canary-rollback-zero'
    assert decision.bucket is None


def test_canary_rejects_rollout_above_twenty_five_percent(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '2501')
    with pytest.raises(KaliNucleiProviderError, match='0 to 2500'):
        nuclei_provider_decision(routing_key='scan-1')


def test_selected_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '2500')
    selected_key = _selected_key()
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('legacy fallback is forbidden'),
    )

    def _failed_kali(**kwargs):
        raise KaliNucleiProviderError('runtime attestation mismatch')

    monkeypatch.setattr(provider, 'execute_kali_nuclei', _failed_kali)
    with pytest.raises(KaliNucleiProviderError, match='attestation mismatch'):
        provider.run_nuclei_with_provider(**_kwargs(selected_key))


def test_selected_kali_result_preserves_runtime_provenance(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '2500')
    selected_key = _selected_key()
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('legacy must not run'),
    )
    monkeypatch.setattr(provider, 'execute_kali_nuclei', lambda **kwargs: _kali_result())
    result = provider.run_nuclei_with_provider(**_kwargs(selected_key))
    assert result.routing['mode'] == 'canary'
    assert result.routing['selected_provider'] == 'kali'
    assert result.runtime == _kali_result()['runtime']


def test_raw_kali_mode_is_rejected_by_production_execution_layer(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'kali')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('legacy must not run'),
    )
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('raw Kali mode must not run'),
    )
    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_nuclei_with_provider(**_kwargs())
