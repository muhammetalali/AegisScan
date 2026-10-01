from __future__ import annotations

import io
import socket
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from fastapi_app.routers import assessment_launcher as launcher
from fastapi_app.services.dynamic_egress import DynamicEgressError, _non_global_network, authorize_dynamic_egress
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


def test_scope_mode_defaults_to_governed_authorization(monkeypatch):
    monkeypatch.delenv('AEGIS_SCAN_SCOPE_MODE', raising=False)
    assert launcher._scope_mode() == 'asset-authorization'


def test_scope_mode_rejects_unknown_values(monkeypatch):
    monkeypatch.setenv('AEGIS_SCAN_SCOPE_MODE', 'anything-goes')
    with pytest.raises(HTTPException, match='AEGIS_SCAN_SCOPE_MODE is invalid'):
        launcher._scope_mode()


def test_single_operator_lab_mode_routes_through_governance_service(monkeypatch):
    monkeypatch.setenv('AEGIS_SCAN_SCOPE_MODE', 'single-operator-lab')
    monkeypatch.setattr(launcher, '_current_authorization', lambda _asset: None)
    monkeypatch.setattr(launcher, 'asset_authorization_version', lambda _asset: 7)

    decision = SimpleNamespace(
        id='decision-1',
        authorized=True,
        target_snapshot='192.168.49.10',
        actor_id='owner-1',
    )
    calls = {}

    def govern(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(decision=decision)

    monkeypatch.setattr(launcher, 'govern_asset_authorization', govern)
    asset = SimpleNamespace(id='asset-1', project_id='project-1')

    result = launcher._ensure_authorization(asset, 'owner-1')

    assert result['state'] == 'authorized'
    assert result['source'] == 'single-operator-lab'
    assert result['decision'] is decision
    assert calls['asset_id'] == 'asset-1'
    assert calls['project_id'] == 'project-1'
    assert calls['actor_id'] == 'owner-1'
    assert calls['expected_version'] == 7
    assert calls['authorized'] is True



def test_dynamic_egress_private_target_fails_closed_without_control_root(monkeypatch):
    monkeypatch.delenv(AEGIS_SCANNER_EGRESS_CONTROL_ROOT, raising=False)
    monkeypatch.setenv(JWT_SECRET_KEY, must-not-be-used-for-egress)
    with pytest.raises(DynamicEgressError, match=AEGIS_SCANNER_EGRESS_CONTROL_ROOT):
        authorize_dynamic_egress([192.168.49.10])


def test_dynamic_egress_public_target_needs_no_control_root(monkeypatch):
    monkeypatch.delenv(AEGIS_SCANNER_EGRESS_CONTROL_ROOT, raising=False)
    monkeypatch.setenv(JWT_SECRET_KEY, must-not-be-used-for-egress)
    authorize_dynamic_egress([93.184.216.34])
