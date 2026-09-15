from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / 'runner' / 'recon_service.py'
SPEC = importlib.util.spec_from_file_location('aegis_recon_service_contract', MODULE_PATH)
assert SPEC and SPEC.loader
recon = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recon
SPEC.loader.exec_module(recon)


@pytest.fixture
def runtime() -> dict:
    tools = {
        'amass': {'version': 'v5.1.1', 'source': 'go'},
        'subfinder': {'version': 'v2.16.0', 'source': 'go'},
        'dnsenum': {'version': '1.3.2-1', 'source': 'kali-apt'},
        'fierce': {'version': '1.6.0-2', 'source': 'kali-apt'},
    }
    return {
        'profile_capabilities': sorted(recon.CAPABILITY_TO_TOOL),
        'profile_tools': tools,
    }


def request(**overrides) -> dict:
    payload = {
        'schema_version': 1,
        'execution_ref': 'scan-123',
        'authorization_ref': 'auth-123',
        'scope_ref': 'project:project-1:asset:asset-1',
        'control_token': 'a' * 64,
        'capability_id': 'recon.subfinder',
        'target': 'example.invalid',
        'options': {},
        'timeout_seconds': 60,
    }
    payload.update(overrides)
    return payload


def test_all_registered_recon_capabilities_have_fixed_tool_paths_and_commands(runtime):
    expected = {
        'recon.amass': ['/usr/local/bin/amass', 'enum', '-passive', '-d', 'example.invalid', '-timeout', '5'],
        'recon.subfinder': ['/usr/local/bin/subfinder', '-d', 'example.invalid', '-silent', '-duc'],
        'recon.dnsenum': ['/usr/bin/dnsenum', 'example.invalid'],
        'recon.fierce': ['/usr/bin/fierce', '--domain', 'example.invalid'],
    }
    for capability_id, command in expected.items():
        options = {'timeout_minutes': 5} if capability_id == 'recon.amass' else {}
        normalized = recon._validate_request(request(capability_id=capability_id, options=options), runtime)
        assert recon._build_command(normalized) == command
        assert normalized['tool'] == recon.CAPABILITY_TO_TOOL[capability_id]


def test_protocol_rejects_raw_command_and_unknown_fields(runtime):
    with pytest.raises(recon.ProtocolError, match='unsupported request fields'):
        recon._validate_request(request(argv=['sh', '-c', 'id']), runtime)
    with pytest.raises(recon.ProtocolError, match='unsupported request fields'):
        recon._validate_request(request(binary='/bin/sh'), runtime)
    with pytest.raises(recon.ProtocolError, match='unsupported request fields'):
        recon._validate_request(request(command='id'), runtime)


def test_protocol_rejects_non_recon_capability_and_missing_bindings(runtime):
    with pytest.raises(recon.ProtocolError, match='not registered'):
        recon._validate_request(request(capability_id='web.httpx'), runtime)
    for field in ('execution_ref', 'authorization_ref', 'scope_ref'):
        with pytest.raises(recon.ProtocolError, match=f'{field} is missing or invalid'):
            recon._validate_request(request(**{field: ''}), runtime)


def test_protocol_rejects_target_injection_and_non_domain_targets(runtime):
    bad_targets = [
        'example.invalid\n--help',
        'https://example.invalid',
        'example.invalid/path',
        '127.0.0.1',
        '-example.invalid',
        'example..invalid',
    ]
    for target in bad_targets:
        with pytest.raises(recon.ProtocolError):
            recon._validate_request(request(target=target), runtime)


def test_protocol_normalizes_domain_and_bounds_amass_timeout(runtime):
    normalized = recon._validate_request(
        request(
            capability_id='recon.amass',
            target='Example.Invalid',
            options={'timeout_minutes': '7'},
            timeout_seconds='450',
        ),
        runtime,
    )
    assert normalized['target'] == 'example.invalid'
    assert normalized['options'] == {'timeout_minutes': 7}
    assert normalized['timeout_seconds'] == 450
    for value in (0, 31, True):
        with pytest.raises(recon.ProtocolError):
            recon._validate_request(
                request(capability_id='recon.amass', options={'timeout_minutes': value}),
                runtime,
            )


def test_non_amass_recon_options_are_rejected(runtime):
    for capability_id in ('recon.subfinder', 'recon.dnsenum', 'recon.fierce'):
        with pytest.raises(recon.ProtocolError, match='does not accept provider options'):
            recon._validate_request(request(capability_id=capability_id, options={'threads': 99}), runtime)


def test_duplicate_json_keys_are_rejected():
    body = (
        b'{"schema_version":1,"execution_ref":"a","execution_ref":"b",'
        b'"authorization_ref":"x","scope_ref":"y","control_token":"' + b'a' * 64 +
        b'","capability_id":"recon.subfinder","target":"example.invalid",'
        b'"options":{},"timeout_seconds":60}'
    )
    with pytest.raises(recon.ProtocolError, match='duplicate JSON field'):
        recon._load_json_bytes(body)


def test_runtime_environment_is_secret_minimized_and_fixed():
    environment = recon._sanitized_environment()
    assert set(environment) == {
        'HOME', 'LANG', 'LC_ALL', 'NO_COLOR', 'PATH', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME'
    }
    assert 'AWS_ACCESS_KEY_ID' not in environment
    assert 'DATABASE_URL' not in environment
    assert 'DJANGO_SETTINGS_MODULE' not in environment


def test_provider_auth_token_is_required_and_strict(monkeypatch):
    monkeypatch.delenv('AEGIS_KALI_RECON_AUTH_TOKEN', raising=False)
    with pytest.raises(RuntimeError, match='64-character lowercase hex token'):
        recon._provider_auth_token()
    for invalid in ('short', 'A' * 64, 'g' * 64):
        monkeypatch.setenv('AEGIS_KALI_RECON_AUTH_TOKEN', invalid)
        with pytest.raises(RuntimeError, match='64-character lowercase hex token'):
            recon._provider_auth_token()
    monkeypatch.setenv('AEGIS_KALI_RECON_AUTH_TOKEN', 'b' * 64)
    assert recon._provider_auth_token() == 'b' * 64


def test_provider_binds_loopback_only_by_contract():
    source = MODULE_PATH.read_text(encoding='utf-8')
    assert "if _LISTEN_HOST != '127.0.0.1'" in source
    assert 'shell=False' in source
    assert 'shell=True' not in source
    assert 'ThreadingHTTPServer((_LISTEN_HOST, _LISTEN_PORT)' in source
