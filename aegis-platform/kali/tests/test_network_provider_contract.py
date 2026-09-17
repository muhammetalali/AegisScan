from __future__ import annotations

import json
from pathlib import Path

KALI = Path(__file__).resolve().parents[1]
REPO = KALI.parents[1]
SERVICE = (KALI / 'runner' / 'network_service.py').read_text(encoding='utf-8')
PROVIDER_DOCKERFILE = (KALI / 'Dockerfile.network-provider').read_text(encoding='utf-8')
PROFILE_DOCKERFILE = (KALI / 'Dockerfile.profiles').read_text(encoding='utf-8')
MANIFEST = json.loads((KALI / 'tool-manifest.json').read_text(encoding='utf-8'))
CANARY_COMPOSE = (REPO / 'aegis-platform' / 'docker-compose.nmap-canary.yml').read_text(encoding='utf-8')
DEFAULT_KALI_COMPOSE = (REPO / 'aegis-platform' / 'docker-compose.nmap-default-kali.yml').read_text(encoding='utf-8')
PROVIDER_CLIENT = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'services' / 'kali_nmap_provider.py'
).read_text(encoding='utf-8')
EXECUTION_PROVIDER = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'services' / 'nmap_execution_provider.py'
).read_text(encoding='utf-8')
TASK = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'tasks' / 'security_scan.py'
).read_text(encoding='utf-8')


def test_shared_network_profile_remains_placement_only():
    network = MANIFEST['profiles']['network']
    assert 'provider_dispatch' not in network
    assert set(network['capabilities']) == {
        'network.nmap', 'network.masscan', 'network.rustscan',
        'network.nbtscan-host', 'network.nbtscan-range',
    }
    assert 'FROM profile-common AS profile-network' in PROFILE_DOCKERFILE


def test_provider_bundle_enables_only_nmap_semantic_dispatch():
    assert "runtime['dispatch_enabled']=True" in PROVIDER_DOCKERFILE
    assert "runtime['dispatch_state']='semantic-network-provider'" in PROVIDER_DOCKERFILE
    assert "runtime['dispatch_capabilities']=['network.nmap']" in PROVIDER_DOCKERFILE
    assert "runtime['provider_bundle']='aegis-kali-network-nmap-canary-v1'" in PROVIDER_DOCKERFILE
    for capability in ('network.masscan', 'network.rustscan', 'network.nbtscan-host', 'network.nbtscan-range'):
        assert capability not in SERVICE


def test_network_service_has_fixed_nmap_semantics_and_no_shell_authority():
    assert "command = [NMAP, '-Pn', '-sV', '-oX', '-', '--', request['target']]" in SERVICE
    assert 'shell=False' in SERVICE
    assert "payload.get('argv')" not in SERVICE
    assert "payload.get('binary')" not in SERVICE
    assert "payload.get('command')" not in SERVICE
    assert "payload.get('capability_id') != 'network.nmap'" in SERVICE
    assert 'network.nmap does not accept provider options' in SERVICE


def test_provider_requires_loopback_auth_provenance_and_net_raw_only():
    assert "parsed.hostname != '127.0.0.1'" in PROVIDER_CLIENT
    assert 'X-Aegis-Network-Token' in PROVIDER_CLIENT
    assert "'0000000000002000'" in PROVIDER_CLIENT
    assert "['CAP_NET_RAW']" in PROVIDER_CLIENT
    assert 'control-plane-deployment-pins' in PROVIDER_CLIENT
    assert 'AEGIS_KALI_NETWORK_EXPECTED_IMAGE_DIGEST' in PROVIDER_CLIENT
    assert 'AEGIS_KALI_NETWORK_EXPECTED_RUNTIME_MANIFEST_DIGEST' in PROVIDER_CLIENT


def test_production_execution_admits_default_kali_but_not_raw_kali_and_has_no_silent_fallback():
    assert "decision.mode not in {'legacy', 'canary', 'default-kali'}" in EXECUTION_PROVIDER
    assert "if decision.selected_provider == 'legacy'" in EXECUTION_PROVIDER
    assert "if decision.selected_provider != 'kali'" in EXECUTION_PROVIDER
    assert 'execute_kali_nmap(' in EXECUTION_PROVIDER
    kali_block = EXECUTION_PROVIDER.split("if decision.selected_provider != 'kali':", 1)[1]
    assert "get_tool('nmap')" not in kali_block


def test_production_nmap_task_uses_scan_identity_and_persists_provider_lineage():
    assert 'result=run_nmap_with_provider(' in TASK
    assert 'routing_key=str(scan.id)' in TASK
    assert 'authorization_ref=str(authorization.id)' in TASK
    assert "scope_ref=f'project:{scan.project_id}:asset:{scan.asset_id}'" in TASK
    assert "'provider_routing':result.routing" in TASK
    assert "'runtime_provenance':result.runtime" in TASK
    assert 'KaliNmapProviderCancelled' in TASK


def test_canary_compose_override_remains_explicit_least_privilege_and_fail_closed():
    assert 'AEGIS_NMAP_PROVIDER: ${AEGIS_NMAP_PROVIDER:-legacy}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_NMAP_CANARY_BPS: ${AEGIS_KALI_NMAP_CANARY_BPS:-0}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_NETWORK_URL: ${AEGIS_KALI_NETWORK_URL:-http://127.0.0.1:18766}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_NETWORK_EXPECTED_IMAGE_DIGEST:' in CANARY_COMPOSE
    assert 'AEGIS_KALI_NETWORK_EXPECTED_RUNTIME_MANIFEST_DIGEST:' in CANARY_COMPOSE
    assert 'kali_network:' in CANARY_COMPOSE
    assert 'profiles: [kali-network]' in CANARY_COMPOSE
    assert 'network_mode: "service:scanner_egress"' in CANARY_COMPOSE
    assert 'cap_drop: [ALL]' in CANARY_COMPOSE
    assert 'cap_add: [NET_RAW]' in CANARY_COMPOSE
    assert 'security_opt: [no-new-privileges:true]' in CANARY_COMPOSE
    assert 'read_only: true' in CANARY_COMPOSE
    assert 'NET_ADMIN' not in CANARY_COMPOSE


def test_default_kali_compose_promotes_nmap_without_broadening_provider_privilege():
    assert 'AEGIS_NMAP_PROVIDER: ${AEGIS_NMAP_PROVIDER:-default-kali}' in DEFAULT_KALI_COMPOSE
    assert 'AEGIS_KALI_NMAP_CANARY_BPS: "0"' in DEFAULT_KALI_COMPOSE
    assert 'AEGIS_KALI_NETWORK_URL: ${AEGIS_KALI_NETWORK_URL:-http://127.0.0.1:18766}' in DEFAULT_KALI_COMPOSE
    assert 'kali_network:' in DEFAULT_KALI_COMPOSE
    assert 'profiles: [kali-network]' in DEFAULT_KALI_COMPOSE
    assert 'network_mode: "service:scanner_egress"' in DEFAULT_KALI_COMPOSE
    assert 'cap_drop: [ALL]' in DEFAULT_KALI_COMPOSE
    assert 'cap_add: [NET_RAW]' in DEFAULT_KALI_COMPOSE
    assert 'security_opt: [no-new-privileges:true]' in DEFAULT_KALI_COMPOSE
    assert 'read_only: true' in DEFAULT_KALI_COMPOSE
    assert 'NET_ADMIN' not in DEFAULT_KALI_COMPOSE
