from __future__ import annotations

import json
from pathlib import Path

KALI = Path(__file__).resolve().parents[1]
REPO = KALI.parents[1]
MANIFEST = json.loads((KALI / 'tool-manifest.json').read_text(encoding='utf-8'))
DOCKERFILE = (KALI / 'Dockerfile.profiles').read_text(encoding='utf-8')
SERVICE = (KALI / 'runner' / 'network_nmap_parity_service.py').read_text(encoding='utf-8')
RUNTIME_BUILDER = (KALI / 'runner' / 'profile_runtime_manifest.py').read_text(encoding='utf-8')


def test_network_nmap_is_pinned_but_not_production_dispatched_during_parity():
    network = MANIFEST['profiles']['network']
    assert 'network.nmap' in network['capabilities']
    assert 'provider_dispatch' not in network
    assert MANIFEST['tools']['nmap']['version'] == '7.99+dfsg-1kali1'
    assert 'nmap=7.99+dfsg-1kali1' in DOCKERFILE
    assert "profile != 'recon'" in RUNTIME_BUILDER


def test_parity_service_is_explicitly_non_production_and_loopback_only():
    assert "AEGIS_KALI_NETWORK_PARITY_MODE" in SERVICE
    assert "dispatch_state') != 'accepted-no-dispatch'" in SERVICE
    assert "_LISTEN_HOST != '127.0.0.1'" in SERVICE
    assert "'network.nmap'" in SERVICE
    assert "[NMAP, '-Pn', '-sV', '-oX', '-', '--', request['target']]" in SERVICE
    assert 'shell=False' in SERVICE
    assert 'shell=True' not in SERVICE
    assert "payload.get('argv')" not in SERVICE
    assert "payload.get('binary')" not in SERVICE


def test_parity_service_is_not_packaged_into_production_network_profile():
    assert 'network_nmap_parity_service.py' not in DOCKERFILE
