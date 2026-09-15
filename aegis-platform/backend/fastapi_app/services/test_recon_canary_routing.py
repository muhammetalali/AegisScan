from __future__ import annotations

import pytest

from fastapi_app.services import kali_recon_provider as provider


def _routing_key_for(*, selected: bool) -> str:
    for index in range(10_000):
        key = f'm4-routing-{index}'
        decision = provider.recon_provider_decision('recon.fierce', routing_key=key)
        if (decision.selected_provider == 'kali') is selected:
            return key
    raise AssertionError('unable to derive deterministic canary routing fixture')


def test_canary_zero_is_immediate_rollback_without_routing_key(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '0')

    decision = provider.recon_provider_decision('recon.fierce')

    assert decision.selected_provider == 'legacy'
    assert decision.parity_approved is True
    assert decision.canary_bps == 0
    assert decision.bucket is None
    assert decision.routing_key_digest == ''
    assert decision.reason == 'canary-rollback-zero'


def test_canary_is_hard_bounded_and_only_parity_approved_capability_can_enter(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2500')

    unapproved = provider.recon_provider_decision('recon.subfinder', routing_key='scan-1')
    assert unapproved.selected_provider == 'legacy'
    assert unapproved.recon_capability is True
    assert unapproved.parity_approved is False
    assert unapproved.bucket is None
    assert unapproved.reason == 'capability-not-parity-approved'

    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2501')
    with pytest.raises(provider.KaliReconProviderError, match='0 to 2500'):
        provider.recon_provider_decision('recon.fierce', routing_key='scan-1')

    for invalid in ('-1', '1.5', 'not-a-number', '10000'):
        monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', invalid)
        with pytest.raises(provider.KaliReconProviderError, match='0 to 2500'):
            provider.recon_provider_decision('recon.fierce', routing_key='scan-1')


def test_canary_assignment_is_deterministic_stable_and_auditable(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2500')

    selected_key = _routing_key_for(selected=True)
    holdback_key = _routing_key_for(selected=False)

    selected_first = provider.recon_provider_decision('recon.fierce', routing_key=selected_key)
    selected_second = provider.recon_provider_decision('recon.fierce', routing_key=selected_key)
    holdback = provider.recon_provider_decision('recon.fierce', routing_key=holdback_key)

    assert selected_first == selected_second
    assert selected_first.schema == 'aegis.recon-provider-routing.v1'
    assert selected_first.selected_provider == 'kali'
    assert selected_first.reason == 'canary-selected'
    assert selected_first.bucket is not None and selected_first.bucket < 2500
    assert len(selected_first.routing_key_digest) == 64
    assert selected_key not in selected_first.routing_key_digest

    assert holdback.selected_provider == 'legacy'
    assert holdback.reason == 'canary-holdback'
    assert holdback.bucket is not None and holdback.bucket >= 2500
    assert len(holdback.routing_key_digest) == 64


def test_active_canary_requires_nonempty_bounded_routing_key(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '1')

    for invalid in (None, '', '   ', 'x' * 256):
        with pytest.raises(provider.KaliReconProviderError, match='routing_key'):
            provider.recon_provider_decision('recon.fierce', routing_key=invalid)


def test_non_recon_never_routes_to_kali_and_explicit_kali_mode_is_preserved(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2500')
    non_recon = provider.recon_provider_decision('web.httpx', routing_key='scan-1')
    assert non_recon.selected_provider == 'legacy'
    assert non_recon.reason == 'capability-not-kali-recon'

    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    explicit = provider.recon_provider_decision('recon.subfinder')
    assert explicit.selected_provider == 'kali'
    assert explicit.reason == 'explicit-kali-mode'
    assert provider.should_use_kali_recon('recon.subfinder') is True


def test_invalid_provider_mode_fails_closed(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'random')
    with pytest.raises(provider.KaliReconProviderError, match='legacy, canary, default-kali, or kali'):
        provider.recon_provider_decision('recon.fierce', routing_key='scan-1')
