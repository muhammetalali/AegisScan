from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_app.services import amass_v5_adapter as adapter


def test_managed_enum_contract_is_exact_and_bounded():
    assert adapter._managed_enum_request(
        ['enum', '-passive', '-d', 'Example.Invalid', '-timeout', '5']
    ) == ('example.invalid', 5)
    assert adapter._managed_enum_request(['-version']) is None

    invalid = (
        ['enum', '-d', 'example.invalid', '-timeout', '5'],
        ['enum', '-passive', '-d', 'example.invalid', '-timeout', '0'],
        ['enum', '-passive', '-d', 'example.invalid', '-timeout', '31'],
        ['enum', '-passive', '-d', 'https://example.invalid', '-timeout', '5'],
        ['subs', '-names', '-d', 'example.invalid'],
    )
    for argv in invalid:
        with pytest.raises(adapter.AdapterError):
            adapter._managed_enum_request(list(argv))


def test_engine_token_is_random_scoped_and_strict(monkeypatch):
    monkeypatch.setattr(adapter.secrets, 'token_hex', lambda size: 'a' * (size * 2))
    assert adapter._new_engine_token() == 'a' * 64

    monkeypatch.setattr(adapter.secrets, 'token_hex', lambda _size: 'NOT-HEX')
    with pytest.raises(adapter.AdapterError, match='authentication token'):
        adapter._new_engine_token()


def test_adapter_environment_is_secret_minimized(tmp_path: Path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'postgres://sensitive')
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'sensitive')
    monkeypatch.setenv('AEGIS_KALI_RECON_AUTH_TOKEN', 'f' * 64)
    monkeypatch.setenv('AEGIS_AMASS_ENGINE_TOKEN', 'e' * 64)
    monkeypatch.setenv('SSL_CERT_FILE', '/tmp/test-ca.pem')

    environment = adapter._minimal_environment(tmp_path)

    assert environment['HOME'].startswith(str(tmp_path))
    assert environment['TMPDIR'].startswith(str(tmp_path))
    assert environment['SSL_CERT_FILE'] == '/tmp/test-ca.pem'
    assert 'DATABASE_URL' not in environment
    assert 'AWS_ACCESS_KEY_ID' not in environment
    assert 'AEGIS_KALI_RECON_AUTH_TOKEN' not in environment
    assert 'AEGIS_AMASS_ENGINE_TOKEN' not in environment
    assert set(environment) <= {
        'HOME', 'LANG', 'LC_ALL', 'NO_COLOR', 'PATH', 'TMPDIR',
        'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
    }


def test_health_probe_rejects_invalid_tokens_without_network_access():
    assert adapter._health_ok('short') is False
    assert adapter._health_ok('G' * 64) is False


def test_diagnostics_are_bounded():
    short = adapter._bounded_diagnostic('one', 'two')
    assert short == 'one\ntwo'

    oversized = adapter._bounded_diagnostic('x' * (adapter.MAX_DIAGNOSTIC_BYTES + 100))
    assert oversized.endswith('[diagnostic truncated]')
    assert len(oversized.encode('utf-8')) <= adapter.MAX_DIAGNOSTIC_BYTES + 32


def test_main_routes_only_governed_enum(monkeypatch):
    observed: list[tuple[str, int]] = []

    def fake_run(target: str, timeout_minutes: int) -> int:
        observed.append((target, timeout_minutes))
        return 0

    monkeypatch.setattr(adapter, '_run_managed_enum', fake_run)
    assert adapter.main(['enum', '-passive', '-d', 'example.invalid', '-timeout', '7']) == 0
    assert observed == [('example.invalid', 7)]
    assert adapter.main(['engine']) == 70
