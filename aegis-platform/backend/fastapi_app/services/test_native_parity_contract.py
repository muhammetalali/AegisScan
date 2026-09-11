from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_app.services.capability_registry import (
    RETIRED_CAPABILITIES,
    RetiredCapabilityError,
    get_capability,
)
from fastapi_app.services.native_packaging import PACKAGED_NATIVE_CAPABILITIES
from fastapi_app.services.native_tool_runtime import (
    NATIVE_TOOL_SPECS,
    build_native_argv,
    effective_native_timeout,
    get_native_tool_spec,
    validate_native_options,
)


def test_all_registered_native_capabilities_are_packaged_and_proven():
    assert set(NATIVE_TOOL_SPECS) == set(PACKAGED_NATIVE_CAPABILITIES)


def test_terrascan_is_retired_with_an_explicit_maintained_replacement():
    assert 'code.terrascan' not in NATIVE_TOOL_SPECS
    assert 'code.terrascan' not in PACKAGED_NATIVE_CAPABILITIES
    assert RETIRED_CAPABILITIES['code.terrascan']['replacement'] == 'code.trivy-config'
    assert 'code.trivy-config' in NATIVE_TOOL_SPECS
    assert 'code.trivy-config' in PACKAGED_NATIVE_CAPABILITIES

    with pytest.raises(RetiredCapabilityError) as exc:
        get_capability('code.terrascan')

    assert exc.value.replacement == 'code.trivy-config'


def test_rustscan_ports_accept_only_explicit_tcp_port_lists():
    spec = get_native_tool_spec('network.rustscan')
    assert validate_native_options(spec, {'ports': '80,0443,65535'})['ports'] == '80,443,65535'

    for invalid in ('0', '65536', '80-90', '80,,443', 'http', '80;443'):
        with pytest.raises(ValueError):
            validate_native_options(spec, {'ports': invalid})


def test_amass_timeout_is_bounded():
    spec = get_native_tool_spec('recon.amass')
    assert validate_native_options(spec, {})['timeout_minutes'] == 5
    assert validate_native_options(spec, {'timeout_minutes': 1})['timeout_minutes'] == 1
    assert effective_native_timeout(spec, {}) == 330
    assert effective_native_timeout(spec, {'timeout_minutes': 1}) == 90
    assert effective_native_timeout(spec, {'timeout_minutes': 30}) == 1830
    with pytest.raises(ValueError):
        validate_native_options(spec, {'timeout_minutes': 31})


def test_feroxbuster_wordlist_must_stay_under_governed_root(tmp_path: Path, monkeypatch):
    root = tmp_path / 'wordlists'
    root.mkdir()
    wordlist = root / 'small.txt'
    wordlist.write_text('admin\nhealth\n', encoding='utf-8')
    monkeypatch.setenv('AEGIS_WORDLIST_ROOT', str(root))

    spec = get_native_tool_spec('web.feroxbuster')
    normalized = validate_native_options(spec, {'wordlist': str(wordlist), 'threads': 2})
    assert normalized['wordlist'] == str(wordlist.resolve())
    assert normalized['threads'] == 2

    outside = tmp_path / 'outside.txt'
    outside.write_text('admin\n', encoding='utf-8')
    with pytest.raises(ValueError, match='AEGIS_WORDLIST_ROOT'):
        validate_native_options(spec, {'wordlist': str(outside)})


def test_trivy_config_argv_is_offline_at_execution_time(tmp_path: Path, monkeypatch):
    fixture = tmp_path / 'iac'
    fixture.mkdir()
    (fixture / 'main.tf').write_text('resource "aws_s3_bucket" "example" {}\n', encoding='utf-8')
    monkeypatch.setattr('fastapi_app.services.native_tool_runtime.shutil.which', lambda binary: '/usr/local/bin/trivy')

    spec = get_native_tool_spec('code.trivy-config')
    argv, target = build_native_argv(spec, str(fixture), {})

    assert target == str(fixture.resolve())
    assert argv[0] == '/usr/local/bin/trivy'
    assert argv[1:7] == [
        '--cache-dir',
        '/opt/trivy-cache',
        'config',
        '--format',
        'json',
        '--quiet',
    ]
    assert '--skip-check-update' in argv
    assert '--skip-version-check' in argv
    assert argv[-1] == str(fixture.resolve())


def test_nikto_adapter_disables_updates_and_uses_secure_file_capture():
    spec = get_native_tool_spec('web.nikto')
    assert '-nocheck' in spec.suffix_args
    assert '-nointeractive' in spec.suffix_args
    assert spec.suffix_args[-2:] == ('-Format', 'json')
    assert spec.capture_mode == 'nikto-json-file'
    assert '/dev/stdout' not in spec.suffix_args
