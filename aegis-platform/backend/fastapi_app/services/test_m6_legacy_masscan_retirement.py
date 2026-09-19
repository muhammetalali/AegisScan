from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import masscan_execution_provider as provider
from fastapi_app.services import masscan_retirement_preflight as preflight
from fastapi_app.services.kali_masscan_provider import KaliMasscanProviderError


def _kwargs() -> dict:
    return {
        'target': '192.0.2.0/24',
        'ports': '22,80',
        'rate': 1000,
        'timeout_seconds': 120,
        'routing_key': 'm6-masscan-retirement',
        'execution_ref': 'scan:m6:masscan',
        'authorization_ref': 'authorization-m6',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _kali_result() -> dict:
    return {
        'tool': 'masscan',
        'target': '192.0.2.0/24',
        'exit_code': 0,
        'stdout': '[]',
        'stderr': '',
        'runtime': {'provider': 'aegis-kali-network-masscan', 'profile': 'network', 'tool': 'masscan'},
    }


def _preflight_env() -> dict[str, str]:
    image_digest = 'sha256:' + ('a' * 64)
    return {
        'AEGIS_MASSCAN_LEGACY_DISABLED': 'true',
        'AEGIS_MASSCAN_PROVIDER': 'default-kali',
        'AEGIS_KALI_MASSCAN_CANARY_BPS': '0',
        'AEGIS_KALI_MASSCAN_URL': 'http://127.0.0.1:18767',
        'AEGIS_KALI_MASSCAN_AUTH_TOKEN': 'b' * 64,
        'AEGIS_KALI_MASSCAN_EXPECTED_RUNNER_VERSION': '0.1.0',
        'AEGIS_KALI_MASSCAN_EXPECTED_BUILD_COMMIT': 'c' * 40,
        'AEGIS_KALI_MASSCAN_EXPECTED_BASE_IMAGE_DIGEST': 'sha256:' + ('d' * 64),
        'AEGIS_KALI_MASSCAN_EXPECTED_TOOL_MANIFEST_DIGEST': 'sha256:' + ('e' * 64),
        'AEGIS_KALI_MASSCAN_EXPECTED_IMAGE_DIGEST': image_digest,
        'AEGIS_KALI_MASSCAN_EXPECTED_RUNTIME_MANIFEST_DIGEST': 'sha256:' + ('f' * 64),
        'AEGIS_KALI_MASSCAN_IMAGE': image_digest,
    }


@pytest.mark.parametrize(('mode', 'bps'), (('legacy', '0'), ('canary', '0'), ('canary', '2500')))
def test_retirement_lock_rejects_legacy_and_canary_routes(monkeypatch, mode, bps):
    monkeypatch.setenv('AEGIS_MASSCAN_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', mode)
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', bps)
    monkeypatch.setattr(provider, 'run_masscan', lambda *args, **kwargs: pytest.fail('retired local Masscan must never execute'))
    monkeypatch.setattr(provider, 'execute_kali_masscan', lambda **kwargs: pytest.fail('retired Canary mode must never execute'))
    with pytest.raises(KaliMasscanProviderError, match='rollback requires the previous release'):
        provider.run_masscan_with_provider(**_kwargs())


def test_retirement_lock_admits_only_default_kali(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '0')
    monkeypatch.setattr(provider, 'run_masscan', lambda *args, **kwargs: pytest.fail('retired local Masscan must never execute'))
    monkeypatch.setattr(provider, 'execute_kali_masscan', lambda **kwargs: _kali_result())
    result = provider.run_masscan_with_provider(**_kwargs())
    assert provider.legacy_masscan_disabled() is True
    assert result.routing['mode'] == 'default-kali'
    assert result.routing['selected_provider'] == 'kali'
    assert result.routing['reason'] == 'default-kali-parity-approved'
    assert result.runtime['provider'] == 'aegis-kali-network-masscan'


def test_retirement_lock_preserves_fail_closed_provider_failure(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'default-kali')
    monkeypatch.setattr(provider, 'run_masscan', lambda *args, **kwargs: pytest.fail('retired local Masscan fallback is forbidden'))
    monkeypatch.setattr(provider, 'execute_kali_masscan', lambda **kwargs: (_ for _ in ()).throw(KaliMasscanProviderError('provider unavailable')))
    with pytest.raises(KaliMasscanProviderError, match='provider unavailable'):
        provider.run_masscan_with_provider(**_kwargs())


def test_raw_kali_mode_stays_unadmitted_after_retirement(monkeypatch):
    monkeypatch.setenv('AEGIS_MASSCAN_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'kali')
    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_masscan_with_provider(**_kwargs())


def test_reference_behavior_remains_available_only_without_retirement_lock(monkeypatch):
    monkeypatch.delenv('AEGIS_MASSCAN_LEGACY_DISABLED', raising=False)
    monkeypatch.setenv('AEGIS_MASSCAN_PROVIDER', 'legacy')
    monkeypatch.setattr(provider, 'run_masscan', lambda target, **kwargs: SimpleNamespace(tool='masscan', target=target, exit_code=0, stdout='[]', stderr=''))
    monkeypatch.setattr(provider, 'execute_kali_masscan', lambda **kwargs: pytest.fail('Kali must not execute in historical reference mode'))
    result = provider.run_masscan_with_provider(**_kwargs())
    assert provider.legacy_masscan_disabled() is False
    assert result.routing['selected_provider'] == 'legacy'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_retirement_startup_preflight_accepts_complete_production_contract():
    assert preflight.validate(_preflight_env()) == []


def test_retirement_startup_preflight_is_reference_safe_when_lock_is_absent():
    assert preflight.validate({'AEGIS_MASSCAN_PROVIDER': 'legacy'}) == []


@pytest.mark.parametrize(
    ('name', 'value', 'expected'),
    (
        ('AEGIS_MASSCAN_PROVIDER', 'legacy', 'must be default-kali'),
        ('AEGIS_KALI_MASSCAN_CANARY_BPS', '2500', 'must be exactly 0'),
        ('AEGIS_KALI_MASSCAN_URL', 'http://kali-masscan:18767', '127.0.0.1'),
        ('AEGIS_KALI_MASSCAN_AUTH_TOKEN', 'short', '64-character'),
        ('AEGIS_KALI_MASSCAN_EXPECTED_BUILD_COMMIT', 'not-a-sha', '40-character'),
        ('AEGIS_KALI_MASSCAN_IMAGE', 'aegis-kali:masscan-provider', 'immutable sha256'),
    ),
)
def test_retirement_startup_preflight_fails_closed_on_policy_drift(name, value, expected):
    environment = _preflight_env()
    environment[name] = value
    failures = preflight.validate(environment)
    assert failures
    assert any(expected in failure for failure in failures), failures


def test_retirement_startup_preflight_rejects_image_digest_mismatch():
    environment = _preflight_env()
    environment['AEGIS_KALI_MASSCAN_IMAGE'] = 'sha256:' + ('1' * 64)
    failures = preflight.validate(environment)
    assert any('must match AEGIS_KALI_MASSCAN_EXPECTED_IMAGE_DIGEST' in failure for failure in failures)
