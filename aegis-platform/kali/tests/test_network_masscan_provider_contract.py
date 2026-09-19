from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

KALI = Path(__file__).resolve().parents[1]
REPO = KALI.parents[1]
SERVICE_PATH = KALI / 'runner' / 'network_masscan_service.py'
SERVICE = SERVICE_PATH.read_text(encoding='utf-8')
DOCKERFILE = (KALI / 'Dockerfile.masscan-provider').read_text(encoding='utf-8')
COMPOSE = (REPO / 'aegis-platform' / 'docker-compose.masscan-canary.yml').read_text(encoding='utf-8')

spec = importlib.util.spec_from_file_location('network_masscan_service', SERVICE_PATH)
assert spec and spec.loader
service = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = service
spec.loader.exec_module(service)


def _request() -> dict:
    return {
        'schema_version': 1,
        'execution_ref': 'scan:1:masscan',
        'authorization_ref': 'authorization-1',
        'scope_ref': 'project:p1:asset:a1',
        'control_token': 'a' * 64,
        'capability_id': 'network.masscan',
        'target': '192.0.2.0/24',
        'options': {
            'ports': '22,80-81',
            'rate': 1000,
            'interface': 'eth0',
            'adapter_ip': '192.0.2.20',
            'adapter_mac': '02:00:00:00:00:20',
            'router_mac': '02:00:00:00:00:01',
        },
        'timeout_seconds': 120,
    }


def test_provider_image_dispatches_only_masscan():
    assert "runtime['dispatch_capabilities']=['network.masscan']" in DOCKERFILE
    assert "runtime['dispatch_state']='semantic-masscan-provider'" in DOCKERFILE
    assert 'network.nmap' not in DOCKERFILE
    assert 'network_masscan_service.py' in DOCKERFILE


def test_service_has_no_raw_command_surface_and_requires_minimum_privilege():
    assert "'network.masscan'" in SERVICE
    assert 'shell=False' in SERVICE
    assert 'shell=True' not in SERVICE
    assert "_NET_RAW_MASK = 1 << 13" in SERVICE
    assert "allowed_capabilities': ['CAP_NET_RAW']" in SERVICE
    assert "'NoNewPrivs'" in SERVICE
    assert 'X-Aegis-Masscan-Token' in SERVICE
    assert '/control' in SERVICE


def test_request_contract_is_semantic_and_bounded():
    runtime = {'profile_capabilities': ['network.masscan']}
    accepted = service._validate_request(_request(), runtime)
    assert accepted['target'] == '192.0.2.0/24'
    assert accepted['ports'] == '22,80-81'
    assert accepted['rate'] == 1000
    assert accepted['interface'] == 'eth0'

    request = _request()
    request['argv'] = ['masscan', '0.0.0.0/0']
    with pytest.raises(service.ProtocolError, match='unsupported request fields'):
        service._validate_request(request, runtime)

    for bad_ports in ('22 80', '22;id', '0', '65536', '100-22'):
        request = _request()
        request['options']['ports'] = bad_ports
        with pytest.raises(service.ProtocolError):
            service._validate_request(request, runtime)

    request = _request()
    request['options']['rate'] = 100001
    with pytest.raises(service.ProtocolError, match='between 1 and 100000'):
        service._validate_request(request, runtime)


def test_canary_compose_is_opt_in_and_keeps_legacy_default():
    assert 'AEGIS_MASSCAN_PROVIDER: ${AEGIS_MASSCAN_PROVIDER:-legacy}' in COMPOSE
    assert 'AEGIS_KALI_MASSCAN_CANARY_BPS: ${AEGIS_KALI_MASSCAN_CANARY_BPS:-0}' in COMPOSE
    assert 'profiles: [kali-masscan]' in COMPOSE
    assert 'network_mode: "service:scanner_egress"' in COMPOSE
    assert 'cap_drop: [ALL]' in COMPOSE
    assert 'cap_add: [NET_RAW]' in COMPOSE
    assert 'no-new-privileges:true' in COMPOSE
    assert 'read_only: true' in COMPOSE
