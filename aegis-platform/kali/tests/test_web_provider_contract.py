from __future__ import annotations

import json
from pathlib import Path

KALI = Path(__file__).resolve().parents[1]
REPO = KALI.parents[1]
SERVICE = (KALI / 'runner' / 'web_service.py').read_text(encoding='utf-8')
PROVIDER_DOCKERFILE = (KALI / 'Dockerfile.web-provider').read_text(encoding='utf-8')
PROFILE_DOCKERFILE = (KALI / 'Dockerfile.profiles').read_text(encoding='utf-8')
MANIFEST = json.loads((KALI / 'tool-manifest.json').read_text(encoding='utf-8'))
CANARY_COMPOSE = (REPO / 'aegis-platform' / 'docker-compose.nuclei-canary.yml').read_text(encoding='utf-8')
PROVIDER_CLIENT = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'services' / 'kali_nuclei_provider.py'
).read_text(encoding='utf-8')
EXECUTION_PROVIDER = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'services' / 'nuclei_execution_provider.py'
).read_text(encoding='utf-8')
TASK = (
    REPO / 'aegis-platform' / 'backend' / 'fastapi_app' / 'tasks' / 'security_scan.py'
).read_text(encoding='utf-8')


def test_shared_web_profile_remains_placement_only():
    web = MANIFEST['profiles']['web']
    assert 'provider_dispatch' not in web
    assert 'web.nuclei' in web['capabilities']
    assert 'FROM profile-common AS profile-web' in PROFILE_DOCKERFILE


def test_provider_bundle_enables_only_nuclei_semantic_dispatch():
    assert "runtime['dispatch_enabled']=True" in PROVIDER_DOCKERFILE
    assert "runtime['dispatch_state']='semantic-web-provider'" in PROVIDER_DOCKERFILE
    assert "runtime['dispatch_capabilities']=['web.nuclei']" in PROVIDER_DOCKERFILE
    assert "runtime['provider_bundle']='aegis-kali-web-nuclei-canary-v1'" in PROVIDER_DOCKERFILE
    for capability in ('web.httpx', 'web.katana', 'web.gobuster', 'web.ffuf', 'web.nikto'):
        assert capability not in SERVICE


def test_web_service_has_fixed_nuclei_semantics_and_no_shell_authority():
    assert "NUCLEI = '/usr/local/bin/nuclei'" in SERVICE
    assert "'-jsonl'" in SERVICE
    assert "'-silent'" in SERVICE
    assert "'-no-color'" in SERVICE
    assert "'-dr'" in SERVICE
    assert 'shell=False' in SERVICE
    assert "payload.get('argv')" not in SERVICE
    assert "payload.get('binary')" not in SERVICE
    assert "payload.get('command')" not in SERVICE
    assert "payload.get('capability_id') != 'web.nuclei'" in SERVICE
    assert 'web.nuclei does not accept provider options' in SERVICE


def test_provider_requires_loopback_auth_provenance_and_zero_capabilities():
    assert "parsed.hostname != '127.0.0.1'" in PROVIDER_CLIENT
    assert 'X-Aegis-Web-Token' in PROVIDER_CLIENT
    assert "'0000000000000000'" in PROVIDER_CLIENT
    assert "privilege.get('allowed_capabilities') != []" in PROVIDER_CLIENT
    assert 'control-plane-deployment-pins' in PROVIDER_CLIENT
    assert 'AEGIS_KALI_WEB_EXPECTED_IMAGE_DIGEST' in PROVIDER_CLIENT
    assert 'AEGIS_KALI_WEB_EXPECTED_RUNTIME_MANIFEST_DIGEST' in PROVIDER_CLIENT


def test_production_execution_admits_governed_modes_and_rejects_raw_kali_without_silent_fallback():
    assert "decision.mode not in {'legacy', 'canary', 'default-kali'}" in EXECUTION_PROVIDER
    assert "if decision.selected_provider == 'legacy'" in EXECUTION_PROVIDER
    assert "if decision.selected_provider != 'kali'" in EXECUTION_PROVIDER
    assert 'execute_kali_nuclei(' in EXECUTION_PROVIDER
    kali_block = EXECUTION_PROVIDER.split("if decision.selected_provider != 'kali':", 1)[1]
    assert 'run_nuclei(' not in kali_block


def test_production_nuclei_task_uses_scan_identity_and_persists_provider_lineage():
    assert 'result=run_nuclei_with_provider(' in TASK
    assert 'routing_key=str(scan.id)' in TASK
    assert 'authorization_ref=str(authorization.id)' in TASK
    assert "scope_ref=f'project:{scan.project_id}:asset:{scan.asset_id}'" in TASK
    assert "'provider_routing':result.routing" in TASK
    assert "'runtime_provenance':result.runtime" in TASK
    assert 'KaliNucleiProviderCancelled' in TASK


def test_canary_compose_override_is_opt_in_least_privilege_and_fail_closed():
    assert 'AEGIS_NUCLEI_PROVIDER: ${AEGIS_NUCLEI_PROVIDER:-legacy}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_NUCLEI_CANARY_BPS: ${AEGIS_KALI_NUCLEI_CANARY_BPS:-0}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_WEB_URL: ${AEGIS_KALI_WEB_URL:-http://127.0.0.1:18770}' in CANARY_COMPOSE
    assert 'AEGIS_KALI_WEB_EXPECTED_IMAGE_DIGEST:' in CANARY_COMPOSE
    assert 'AEGIS_KALI_WEB_EXPECTED_RUNTIME_MANIFEST_DIGEST:' in CANARY_COMPOSE
    assert 'kali_web:' in CANARY_COMPOSE
    assert 'profiles: [kali-web]' in CANARY_COMPOSE
    assert 'network_mode: "service:scanner_egress"' in CANARY_COMPOSE
    assert 'cap_drop: [ALL]' in CANARY_COMPOSE
    assert 'cap_add:' not in CANARY_COMPOSE
    assert 'security_opt: [no-new-privileges:true]' in CANARY_COMPOSE
    assert 'read_only: true' in CANARY_COMPOSE
    assert 'user: "10001:10001"' in CANARY_COMPOSE
