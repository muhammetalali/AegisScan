from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_app.services import semgrep_execution_provider as provider
from fastapi_app.services import semgrep_retirement_preflight as preflight
from fastapi_app.services.kali_semgrep_provider import KaliSemgrepProviderError


def _source(tmp_path: Path) -> str:
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'app.py').write_text('def f(x):\n    return eval(x)\n', encoding='utf-8')
    return str(source)


def _kwargs(tmp_path: Path) -> dict:
    return {
        'source': _source(tmp_path),
        'timeout_seconds': 120,
        'routing_key': 'm6-semgrep-retirement',
        'execution_ref': 'scan:m6:semgrep',
        'authorization_ref': 'authorization-m6',
        'scope_ref': 'project:p1:asset:code',
        'state_getter': lambda: 'running',
    }


def _kali_result() -> dict:
    return {
        'tool': 'semgrep',
        'exit_code': 0,
        'stdout': json.dumps({'results': [], 'errors': []}),
        'stderr': '',
        'runtime': {
            'provider': 'aegis-kali-code',
            'profile': 'code',
            'tool': 'semgrep',
            'provenance_authority': 'control-plane-deployment-pins',
        },
    }


def _preflight_env() -> dict[str, str]:
    image_digest = 'sha256:' + ('a' * 64)
    return {
        'AEGIS_SEMGREP_LEGACY_DISABLED': 'true',
        'AEGIS_SEMGREP_PROVIDER': 'default-kali',
        'AEGIS_KALI_SEMGREP_CANARY_BPS': '0',
        'AEGIS_SEMGREP_WORKSPACE_ROOT': '/var/lib/aegis-semgrep',
        'AEGIS_KALI_CODE_URL': 'http://127.0.0.1:18771',
        'AEGIS_KALI_CODE_AUTH_TOKEN': 'b' * 64,
        'AEGIS_KALI_CODE_EXPECTED_RUNNER_VERSION': '0.1.0',
        'AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT': 'c' * 40,
        'AEGIS_KALI_CODE_EXPECTED_BASE_IMAGE_DIGEST': 'sha256:' + ('d' * 64),
        'AEGIS_KALI_CODE_EXPECTED_TOOL_MANIFEST_DIGEST': 'sha256:' + ('e' * 64),
        'AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST': image_digest,
        'AEGIS_KALI_CODE_EXPECTED_RUNTIME_MANIFEST_DIGEST': 'sha256:' + ('f' * 64),
        'AEGIS_KALI_CODE_IMAGE': image_digest,
    }


@pytest.mark.parametrize(
    ('mode', 'bps'),
    (('legacy', '0'), ('canary', '0'), ('canary', '2500')),
)
def test_retirement_lock_rejects_legacy_and_canary_routes(monkeypatch, tmp_path, mode, bps):
    monkeypatch.setenv('AEGIS_SEMGREP_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', mode)
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', bps)
    monkeypatch.setattr(
        provider,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('retired local Semgrep must never execute'),
    )
    monkeypatch.setattr(
        provider,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('retired Canary mode must never execute'),
    )

    with pytest.raises(KaliSemgrepProviderError, match='rollback requires the previous release'):
        provider.run_semgrep_with_provider(**_kwargs(tmp_path))


def test_retirement_lock_admits_only_default_kali(monkeypatch, tmp_path):
    monkeypatch.setenv('AEGIS_SEMGREP_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '0')
    monkeypatch.setenv('AEGIS_SEMGREP_WORKSPACE_ROOT', str(tmp_path / 'workspace'))
    monkeypatch.setattr(
        provider,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('retired local Semgrep must never execute'),
    )
    monkeypatch.setattr(provider, 'execute_kali_semgrep', lambda **kwargs: _kali_result())

    result = provider.run_semgrep_with_provider(**_kwargs(tmp_path))

    assert provider.legacy_semgrep_disabled() is True
    assert result.routing['mode'] == 'default-kali'
    assert result.routing['selected_provider'] == 'kali'
    assert result.routing['reason'] == 'default-kali-parity-approved'
    assert result.runtime['provider'] == 'aegis-kali-code'
    assert not any((tmp_path / 'workspace').iterdir())


def test_retirement_lock_preserves_fail_closed_provider_failure(monkeypatch, tmp_path):
    monkeypatch.setenv('AEGIS_SEMGREP_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '0')
    monkeypatch.setenv('AEGIS_SEMGREP_WORKSPACE_ROOT', str(tmp_path / 'workspace'))
    monkeypatch.setattr(
        provider,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('retired local Semgrep fallback is forbidden'),
    )

    def _failed_provider(**kwargs):
        raise KaliSemgrepProviderError('provider unavailable')

    monkeypatch.setattr(provider, 'execute_kali_semgrep', _failed_provider)
    with pytest.raises(KaliSemgrepProviderError, match='provider unavailable'):
        provider.run_semgrep_with_provider(**_kwargs(tmp_path))


def test_raw_kali_mode_stays_unadmitted_after_retirement(monkeypatch, tmp_path):
    monkeypatch.setenv('AEGIS_SEMGREP_LEGACY_DISABLED', 'true')
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'kali')
    monkeypatch.setattr(
        provider,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('retired local Semgrep must never execute'),
    )
    monkeypatch.setattr(
        provider,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('raw Kali mode must never execute'),
    )

    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        provider.run_semgrep_with_provider(**_kwargs(tmp_path))


def test_reference_behavior_remains_available_only_without_retirement_lock(monkeypatch, tmp_path):
    monkeypatch.delenv('AEGIS_SEMGREP_LEGACY_DISABLED', raising=False)
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'legacy')

    def _reference(source, *, timeout, state_getter):
        assert timeout == 120
        assert state_getter() == 'running'
        return SimpleNamespace(
            tool='semgrep',
            target=source,
            exit_code=0,
            stdout=json.dumps({'results': [], 'errors': []}),
            stderr='',
        )

    monkeypatch.setattr(provider, 'run_semgrep', _reference)
    monkeypatch.setattr(
        provider,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('Kali must not execute in historical reference mode'),
    )

    result = provider.run_semgrep_with_provider(**_kwargs(tmp_path))
    assert provider.legacy_semgrep_disabled() is False
    assert result.routing['selected_provider'] == 'legacy'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_retirement_startup_preflight_accepts_complete_production_contract():
    assert preflight.validate(_preflight_env()) == []


def test_retirement_startup_preflight_is_reference_safe_when_lock_is_absent():
    assert preflight.validate({'AEGIS_SEMGREP_PROVIDER': 'legacy'}) == []


@pytest.mark.parametrize(
    ('name', 'value', 'expected'),
    (
        ('AEGIS_SEMGREP_PROVIDER', 'legacy', 'must be default-kali'),
        ('AEGIS_KALI_SEMGREP_CANARY_BPS', '2500', 'must be exactly 0'),
        ('AEGIS_SEMGREP_WORKSPACE_ROOT', '/tmp/workspace', '/var/lib/aegis-semgrep'),
        ('AEGIS_KALI_CODE_URL', 'http://kali-code:18771', '127.0.0.1'),
        ('AEGIS_KALI_CODE_AUTH_TOKEN', 'short', '64-character'),
        ('AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT', 'not-a-sha', '40-character'),
        ('AEGIS_KALI_CODE_IMAGE', 'aegis-kali:code-provider', 'immutable sha256'),
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
    environment['AEGIS_KALI_CODE_IMAGE'] = 'sha256:' + ('1' * 64)
    failures = preflight.validate(environment)
    assert any('must match AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST' in failure for failure in failures)
