from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

KALI = Path(__file__).resolve().parents[1]
REPO = KALI.parents[1]
MANIFEST = json.loads((KALI / 'tool-manifest.json').read_text(encoding='utf-8'))
DOCKERFILE = (KALI / 'Dockerfile.profiles').read_text(encoding='utf-8')
SERVICE_PATH = KALI / 'runner' / 'network_masscan_parity_service.py'
SERVICE = SERVICE_PATH.read_text(encoding='utf-8')
RUNTIME_BUILDER = (KALI / 'runner' / 'profile_runtime_manifest.py').read_text(encoding='utf-8')
CONTRACT_WORKFLOW = (REPO / '.github' / 'workflows' / 'network-masscan-parity-reality.yml').read_text(encoding='utf-8')
REAL_WORKFLOW = (REPO / '.github' / 'workflows' / 'network-masscan-real-parity.yml').read_text(encoding='utf-8')

spec = importlib.util.spec_from_file_location('network_masscan_parity_service', SERVICE_PATH)
assert spec and spec.loader
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


def _bound_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_PARITY_AUTH_TOKEN', 'a' * 64)
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_EXPECTED_AUTHORIZATION_REF', 'masscan-parity-authorization')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_EXPECTED_SCOPE_REF', 'project:parity:asset:masscan')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_EXPECTED_TARGET', '172.31.1.10')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_EXPECTED_PORTS', '22,80')
    monkeypatch.setenv('AEGIS_KALI_MASSCAN_EXPECTED_RATE', '1000')


def _request() -> dict:
    return {
        'schema_version': 1,
        'execution_ref': 'masscan-parity-execution',
        'authorization_ref': 'masscan-parity-authorization',
        'scope_ref': 'project:parity:asset:masscan',
        'capability_id': 'network.masscan',
        'target': '172.31.1.10',
        'options': {'ports': '22,80', 'rate': 1000},
        'timeout_seconds': 120,
    }


def test_network_masscan_is_pinned_but_not_production_dispatched_during_parity():
    network = MANIFEST['profiles']['network']
    assert 'network.masscan' in network['capabilities']
    assert 'provider_dispatch' not in network
    assert MANIFEST['tools']['masscan']['version'] == '2:1.3.2+ds1-2'
    assert 'masscan=2:1.3.2+ds1-2' in DOCKERFILE
    assert "profile != 'recon'" in RUNTIME_BUILDER


def test_parity_service_is_explicitly_non_production_loopback_and_semantic_only():
    assert 'AEGIS_KALI_MASSCAN_PARITY_MODE' in SERVICE
    assert "dispatch_state') != 'accepted-no-dispatch'" in SERVICE
    assert "_LISTEN_HOST != '127.0.0.1'" in SERVICE
    assert "'network.masscan'" in SERVICE
    assert "'--output-format', 'json'" in SERVICE
    assert 'shell=False' in SERVICE
    assert 'shell=True' not in SERVICE
    assert "payload.get('argv')" not in SERVICE
    assert "payload.get('binary')" not in SERVICE
    assert "_NET_RAW_MASK = 1 << 13" in SERVICE
    assert "'NoNewPrivs'" in SERVICE


def test_request_is_bound_to_authorization_scope_target_and_scan_intent(monkeypatch: pytest.MonkeyPatch):
    _bound_env(monkeypatch)
    runtime = {'profile_capabilities': ['network.masscan']}
    accepted = service._validate_request(_request(), runtime)
    assert accepted['authorization_ref'] == 'masscan-parity-authorization'
    assert accepted['scope_ref'] == 'project:parity:asset:masscan'
    assert accepted['target'] == '172.31.1.10'
    assert accepted['ports'] == '22,80'
    assert accepted['rate'] == 1000

    mutations = [
        ('authorization_ref', 'wrong-authorization'),
        ('scope_ref', 'project:other:asset:masscan'),
        ('target', '172.31.1.11'),
    ]
    for field, value in mutations:
        request = _request()
        request[field] = value
        with pytest.raises(service.ProtocolError):
            service._validate_request(request, runtime)

    request = _request()
    request['options'] = {'ports': '22,443', 'rate': 1000}
    with pytest.raises(service.ProtocolError, match='ports do not match'):
        service._validate_request(request, runtime)

    request = _request()
    request['options'] = {'ports': '22,80', 'rate': 2000}
    with pytest.raises(service.ProtocolError, match='rate does not match'):
        service._validate_request(request, runtime)


def test_request_rejects_raw_or_unsafe_command_surface(monkeypatch: pytest.MonkeyPatch):
    _bound_env(monkeypatch)
    runtime = {'profile_capabilities': ['network.masscan']}
    request = _request()
    request['argv'] = ['masscan', 'unbound-target']
    with pytest.raises(service.ProtocolError, match='unsupported request fields'):
        service._validate_request(request, runtime)
    for bad_ports in ('22 80', '22;id', '0', '65536', '100-22'):
        with pytest.raises(service.ProtocolError):
            service._canonical_ports(bad_ports)


def test_real_parity_runtime_uses_only_net_raw_and_no_new_privileges():
    assert '--cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true' in REAL_WORKFLOW
    assert '--cap-add NET_ADMIN' not in REAL_WORKFLOW
    assert "privilege['effective']=='0000000000002000'" in REAL_WORKFLOW
    assert "privilege['allowed_capabilities']==['CAP_NET_RAW']" in REAL_WORKFLOW
    assert 'docker network create --internal' in REAL_WORKFLOW


def test_parity_service_is_not_packaged_or_selected_as_production_provider():
    assert 'network_masscan_parity_service.py' not in DOCKERFILE
    assert 'AEGIS_MASSCAN_PROVIDER' not in SERVICE
    assert 'production_cutover' in CONTRACT_WORKFLOW
    assert "'production_cutover':False" in CONTRACT_WORKFLOW
    assert "'legacy_retirement':False" in CONTRACT_WORKFLOW
    assert "'candidate_production_dispatch':False" in REAL_WORKFLOW
