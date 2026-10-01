from __future__ import annotations

import io
import socket
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fastapi_app.routers import assessment_launcher as launcher
from fastapi_app.services.dynamic_egress import _non_global_network
from fastapi_app.services.scanner_adapters import validate_code_target


def _dns(address: str):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return (family, socket.SOCK_STREAM, 6, '', sockaddr)


def test_launcher_normalizes_network_and_ip_targets():
    asset_type, target, config = launcher._normalize_target('network', '192.168.49.33/24')
    assert asset_type == 'network_range'
    assert target == '192.168.49.0/24'
    assert config == {'cidr': '192.168.49.0/24'}

    asset_type, target, config = launcher._normalize_target('ip', '192.168.49.10')
    assert asset_type == 'ip_address'
    assert target == '192.168.49.10'
    assert config == {'ip': '192.168.49.10'}


def test_launcher_url_defaults_https_and_pins_dns(monkeypatch):
    monkeypatch.setattr(
        launcher.socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [_dns('192.168.49.20')],
    )
    asset_type, target, config = launcher._normalize_target('url', 'internal.example/app')
    assert asset_type == 'website'
    assert target == 'https://internal.example/app'
    assert config['url'] == target
    assert config['resolved_ips'] == ['192.168.49.20']


def test_launcher_rejects_unresolvable_url(monkeypatch):
    def fail(*_args, **_kwargs):
        raise socket.gaierror('synthetic failure')

    monkeypatch.setattr(launcher.socket, 'getaddrinfo', fail)
    with pytest.raises(HTTPException, match='Target DNS resolution failed'):
        launcher._normalize_target('url', 'internal.example')


def test_file_asset_has_semgrep_execution_plan():
    planned = launcher._capability_plan(SimpleNamespace(type='file'), 'standard')
    assert 'code.semgrep' in planned['recommended_capabilities']


def test_safe_zip_extract_rejects_path_traversal(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('../escape.py', 'print("bad")')
    with pytest.raises(HTTPException, match='unsafe path'):
        launcher._safe_extract_zip(stream.getvalue(), tmp_path)


def test_safe_zip_extracts_regular_source(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('src/app.py', 'print("ok")')
    root = launcher._safe_extract_zip(stream.getvalue(), tmp_path)
    assert (root / 'src' / 'app.py').read_text() == 'print("ok")'


def test_validate_code_target_accepts_regular_file_and_rejects_symlink(tmp_path):
    source = tmp_path / 'app.py'
    source.write_text('print("ok")')
    assert validate_code_target(str(source)) == str(source.resolve())

    link = tmp_path / 'alias.py'
    link.symlink_to(source)
    with pytest.raises(ValueError, match='symlink'):
        validate_code_target(str(link))


def test_dynamic_egress_only_materializes_non_global_destinations():
    assert _non_global_network('192.168.49.0/24') == '192.168.49.0/24'
    assert _non_global_network('10.20.30.40') == '10.20.30.40'
    assert _non_global_network('93.184.216.34') is None
