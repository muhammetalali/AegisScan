from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import nuclei_execution_provider as provider
from fastapi_app.services import nuclei_retirement_preflight as preflight
from fastapi_app.services.kali_nuclei_provider import KaliNucleiProviderError


def _kwargs() -> dict:
    return {
        'target': 'http://192.0.2.20',
        'timeout_seconds': 120,
        'routing_key': 'm6-retirement',
        'execution_ref': 'scan:m6:nuclei',
        'authorization_ref': 'authorization-m6',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _kali_result() -> dict:
    return {
        'tool': 'nuclei',
        'target': 'http://192.0.2.20',
        'exit_code': 0,
        'stdout': '{"template-id":"fixture"}\n',
        'stderr': '',
        'runtime': {
            'provider': 'aegis-kali-web',
            'profile': 'web',
            'tool': 'nuclei',
            'provenance_authority': 'control-plane-deployment-pins',
        },
    }


def _preflight_env() -> dict[str, str]:
    image_digest = 'sha256:' + ('a' * 64)
    return {
        'AEGIS_NUCLEI_LEGACY_DISABLED': 'true',
        'AEGIS_NUCLEI_PROVIDER': 'default-kali',
        'AEGIS_KALI_NUCLEI_CANARY_BPS': '0',
        'AEGIS_KALI_WEB_URL': 'http://127.0.0.1:18770',
        'AEGIS_KALI_WEB_AUTH_TOKEN': 'b' * 64,
        'AEGIS_KALI_WEB_EXPECTED_RUNNER_VERSION': '0.1.0',
        'AEGIS_KALI_WEB_EXPECTED_BUILD_COMMIT': 'c' * 40,
        'AEGIS_KALI_WEB_EXPECTED_BASE_IMAGE_DIGEST': 'sha256:' + ('d' * 64),
        'AEGIS_KALI_WEB_EXPECTED_TOOL_MANIFEST_DIGEST': 'sha256:' + ('e' * 64),
        'AEGIS_KALI_WEB_EXPECTED_IMAGE_DIGEST': image_digest,
        'AEGIS_KALI_WEB_EXPECTED_RUNTIME_MANIFEST_DIGEST': 'sha256:' + ('f' * 64),
        'AEGIS_KALI_WEB_IMAGE': image_digest,
    }


@pytest.mark.parametrize(
    ('mode', 'bps'),
    (('legacy', '0'), ('canary', '0'), ('canary', '2500')),
)
def test_retirement_lock_rejects_legacy_and_canary_routes(monkeypatch, mode, bps):
    monkeypatch.setenv('AEGIS_NUCLEI_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', mode)
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', bps)
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('retired local Nuclei must never execute'),
    )
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('retired Canary mode must never execute'),
    )

    with pytest.raises(KaliNucleiProviderError, match='rollback requires the previous release'):
        provider.run_nuclei_with_provider(**_kwargs())


def test_retirement_lock_admits_only_default_kali(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_NUCLEI_CANARY_BPS', '0')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('retired local Nuclei must never execute'),
    )
    monkeypatch.setattr(provider, 'execute_kali_nuclei', lambda **kwargs: _kali_result())

    result = provider.run_nuclei_with_provider(**_kwargs())

    assert provider.legacy_nuclei_disabled() is True
    assert result.routing['mode'] == 'default-kali'
    assert result.routing['selected_provider'] == 'kali'
    assert result.routing['reason'] == 'default-kali-parity-approved'
    assert result.runtime['provider'] == 'aegis-kali-web'


def test_retirement_lock_preserves_fail_closed_provider_failure(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'default-kali')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('retired local Nuclei fallback is forbidden'),
    )

    def _failed_provider(**kwargs):
        raise KaliNucleiProviderError('provider unavailable')

    monkeypatch.setattr(provider, 'execute_kali_nuclei', _failed_provider)
    with pytest.raises(KaliNucleiProviderError, match='provider unavailable'):
        provider.run_nuclei_with_provider(**_kwargs())


def test_raw_kali_mode_stays_unadmitted_after_retirement(monkeypatch):
    monkeypatch.setenv('AEGIS_NUCLEI_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'kali')
    monkeypatch.setattr(
        provider,
        'run_nuclei',
        lambda *args, **kwargs: pytest.fail('retired local Nuclei must never execute'),
    )
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('raw Kali mode must never execute'),
    )

    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_nuclei_with_provider(**_kwargs())


def test_reference_behavior_remains_available_only_without_retirement_lock(monkeypatch):
    monkeypatch.delenv('AEGIS_NUCLEI_LEGACY_DISABLED', raising=False)
    monkeypatch.setenv('AEGIS_NUCLEI_PROVIDER', 'legacy')

    def _reference(target, *, timeout, state_getter):
        assert timeout == 120
        assert state_getter() == 'running'
        return SimpleNamespace(
            tool='nuclei',
            target=target,
            exit_code=0,
            stdout='{"template-id":"fixture"}\n',
            stderr='',
        )

    monkeypatch.setattr(provider, 'run_nuclei', _reference)
    monkeypatch.setattr(
        provider,
        'execute_kali_nuclei',
        lambda **kwargs: pytest.fail('Kali must not execute in historical reference mode'),
    )

    result = provider.run_nuclei_with_provider(**_kwargs())
    assert provider.legacy_nuclei_disabled() is False
    assert result.routing['selected_provider'] == 'legacy'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_retirement_startup_preflight_accepts_complete_production_contract():
    assert preflight.validate(_preflight_env()) == []


def test_retirement_startup_preflight_is_reference_safe_when_lock_is_absent():
    assert preflight.validate({'AEGIS_NUCLEI_PROVIDER': 'legacy'}) == []


@pytest.mark.parametrize(
    ('name', 'value', 'expected'),
    (
        ('AEGIS_NUCLEI_PROVIDER', 'legacy', 'must be default-kali'),
        ('AEGIS_KALI_NUCLEI_CANARY_BPS', '2500', 'must be exactly 0'),
        ('AEGIS_KALI_WEB_URL', 'http://kali-web:18770', '127.0.0.1'),
        ('AEGIS_KALI_WEB_AUTH_TOKEN', 'short', '64-character'),
        ('AEGIS_KALI_WEB_EXPECTED_BUILD_COMMIT', 'not-a-sha', '40-character'),
        ('AEGIS_KALI_WEB_IMAGE', 'aegis-kali:web-provider', 'immutable sha256'),
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
    environment['AEGIS_KALI_WEB_IMAGE'] = 'sha256:' + ('1' * 64)
    failures = preflight.validate(environment)
    assert any('must match AEGIS_KALI_WEB_EXPECTED_IMAGE_DIGEST' in failure for failure in failures)
