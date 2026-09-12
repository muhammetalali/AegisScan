from __future__ import annotations

import json
import uuid

import pytest

from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.services.web_security_foundation import (
    analyze_response_pair,
    evaluate_authorization_case,
    evaluate_execution_budget,
    evaluate_negative_invariant,
    evaluate_provider_gate,
    persist_budget,
    persist_policy,
    persist_provider_approval,
    response_semantics,
    run_authorization_matrix,
)


def _user_project(prefix: str = 'web-foundation'):
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f'{prefix}-{suffix}@example.com',
        password='Aegis-Test-Only-Password!42',
        first_name='Web',
        last_name='Security',
    )
    project = Project.objects.create(
        name=f'{prefix}-{suffix}',
        slug=f'{prefix}-{suffix}',
        owner=user,
        environment=Project.Environment.STAGING,
    )
    return user, project


def test_response_semantic_analyzer_normalizes_volatile_fields_and_detects_volume_change(settings):
    settings.SECRET_KEY = 'semantic-test-secret-key'
    baseline = {
        'status_code': 200,
        'headers': {'Content-Type': 'application/json', 'X-Request-ID': 'req-a'},
        'body': {
            'request_id': 'req-a',
            'timestamp': '2026-09-12T10:00:00Z',
            'results': [{'id': 1, 'name': 'alpha'}, {'id': 2, 'name': 'beta'}],
        },
        'timing_ms': 40.0,
    }
    same = {
        'status_code': 200,
        'headers': {'Content-Type': 'application/json', 'X-Request-ID': 'req-b'},
        'body': {
            'request_id': 'req-b',
            'timestamp': '2026-09-12T10:01:00Z',
            'results': [{'id': 1, 'name': 'alpha'}, {'id': 2, 'name': 'beta'}],
        },
        'timing_ms': 45.0,
    }
    changed = {
        **same,
        'body': {
            'request_id': 'req-c',
            'timestamp': '2026-09-12T10:02:00Z',
            'results': [{'id': 1, 'name': 'alpha'}],
        },
    }

    normalized = analyze_response_pair(baseline, same)
    assert normalized['same_semantic_body'] is True
    assert normalized['same_structure'] is True
    assert normalized['record_volume_delta'] == 0

    delta = analyze_response_pair(baseline, changed)
    assert delta['same_semantic_body'] is False
    assert delta['same_structure'] is False
    assert delta['record_volume_delta'] == -1


def test_privacy_preserving_semantics_redact_sensitive_values_and_hmac_tenant_owner(settings):
    settings.SECRET_KEY = 'privacy-test-secret-key'
    response = {
        'status_code': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': {
            'tenant_id': 'tenant-super-secret',
            'owner_id': 'user-sensitive-77',
            'access_token': 'bearer-secret-value',
            'password': 'never-persist-this',
            'profile': {'name': 'Ada'},
        },
    }
    semantic = response_semantics(response)
    rendered = json.dumps(semantic, sort_keys=True)

    assert 'tenant-super-secret' not in rendered
    assert 'user-sensitive-77' not in rendered
    assert 'bearer-secret-value' not in rendered
    assert 'never-persist-this' not in rendered
    assert semantic['sensitive_field_paths'] == ['access_token', 'password']
    assert len(semantic['tenant_value_hmacs']) == 1
    assert len(semantic['owner_value_hmacs']) == 1
    assert all(len(value) == 64 for value in semantic['tenant_value_hmacs'] + semantic['owner_value_hmacs'])


def test_negative_path_engine_rejects_error_leakage_and_missing_headers(settings):
    settings.SECRET_KEY = 'negative-path-test-secret'
    leaked = evaluate_negative_invariant({
        'ref': 'anon-private-resource',
        'type': 'deny_access',
        'response': {
            'status_code': 403,
            'headers': {},
            'body': {'error': 'Traceback (most recent call last): django.core.exceptions.PermissionDenied'},
            'timing_ms': 20,
        },
    })
    assert leaked['passed'] is False
    assert any('leakage' in failure for failure in leaked['failures'])

    missing_headers = evaluate_negative_invariant({
        'ref': 'security-headers',
        'type': 'security_headers',
        'required_headers': ['content-security-policy', 'x-content-type-options'],
        'response': {
            'status_code': 200,
            'headers': {'X-Content-Type-Options': 'nosniff'},
            'body': {'ok': True},
            'timing_ms': 10,
        },
    })
    assert missing_headers['passed'] is False
    assert missing_headers['failures'] == ['missing security header: content-security-policy']


@pytest.mark.django_db
def test_authorization_matrix_proves_same_tenant_and_cross_tenant_semantics(settings):
    settings.SECRET_KEY = 'authorization-matrix-test-secret'
    user, project = _user_project('authorization-matrix')
    policy, created = persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '*/orders/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'order',
        'allowed': True,
        'ownership_rule': 'owner_only',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': ['orders:read'],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {'source_ref': 'fixture://authorization-matrix'},
        'confidence': 1.0,
        'version': 1,
    })
    assert created is True
    assert len(policy.canonical_sha256) == 64

    identity = {
        'ref': 'alice',
        'type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': ['orders:read'],
    }
    cases = [
        {
            'ref': 'same-tenant-owner-allowed',
            'identity': identity,
            'resource': {'ref': 'order-51', 'type': 'order', 'tenant_ref': 'tenant-a', 'owner_ref': 'alice'},
            'endpoint': '/fixed/orders/51',
            'method': 'GET',
            'operation': 'read',
            'protocol': 'https',
            'response': {'status_code': 200, 'headers': {}, 'body': {'id': 51, 'owner_id': 'alice', 'tenant_id': 'tenant-a'}},
        },
        {
            'ref': 'cross-tenant-correctly-denied',
            'identity': identity,
            'resource': {'ref': 'order-74', 'type': 'order', 'tenant_ref': 'tenant-b', 'owner_ref': 'bob'},
            'endpoint': '/fixed/orders/74',
            'method': 'GET',
            'operation': 'read',
            'protocol': 'https',
            'response': {'status_code': 404, 'headers': {}, 'body': {'detail': 'Not found'}},
        },
        {
            'ref': 'cross-tenant-vulnerable-allowed',
            'identity': identity,
            'resource': {'ref': 'order-74', 'type': 'order', 'tenant_ref': 'tenant-b', 'owner_ref': 'bob'},
            'endpoint': '/vulnerable/orders/74',
            'method': 'GET',
            'operation': 'read',
            'protocol': 'https',
            'response': {'status_code': 200, 'headers': {}, 'body': {'id': 74, 'owner_id': 'bob', 'tenant_id': 'tenant-b'}},
        },
        {
            'ref': 'unmanifested-delete-fail-closed',
            'identity': identity,
            'resource': {'ref': 'order-51', 'type': 'order', 'tenant_ref': 'tenant-a', 'owner_ref': 'alice'},
            'endpoint': '/fixed/orders/51',
            'method': 'DELETE',
            'operation': 'delete',
            'protocol': 'https',
            'response': {'status_code': 403, 'headers': {}, 'body': {'detail': 'Forbidden'}},
        },
    ]
    run, observations = run_authorization_matrix(project, str(user.id), cases)
    by_ref = {item.case_ref: item for item in observations}

    assert run.summary == {'total': 4, 'passed': 3, 'failed': 1, 'cross_tenant_cases': 2}
    assert by_ref['same-tenant-owner-allowed'].passed is True
    assert by_ref['cross-tenant-correctly-denied'].passed is True
    assert by_ref['cross-tenant-correctly-denied'].expected_allowed is False
    assert by_ref['cross-tenant-vulnerable-allowed'].passed is False
    assert by_ref['cross-tenant-vulnerable-allowed'].expected_allowed is False
    assert by_ref['cross-tenant-vulnerable-allowed'].observed_decision == 'allowed'
    assert by_ref['unmanifested-delete-fail-closed'].policy_id is None
    assert by_ref['unmanifested-delete-fail-closed'].expected_allowed is False
    assert by_ref['unmanifested-delete-fail-closed'].passed is True

    kinds = set(project.security_graph_nodes.values_list('kind', flat=True))
    assert {'identity', 'tenant', 'resource', 'endpoint', 'policy'}.issubset(kinds)


@pytest.mark.django_db
def test_authorization_policy_fails_closed_when_required_binding_or_condition_evaluator_is_missing(settings):
    settings.SECRET_KEY = 'authorization-binding-test-secret'
    user, project = _user_project('authorization-binding')
    tenant_policy, _ = persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '/bound/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'record',
        'allowed': True,
        'ownership_rule': 'owner_only',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': [],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {'source_ref': 'fixture://binding'},
        'confidence': 1.0,
        'version': 1,
    })
    missing_tenant = evaluate_authorization_case([tenant_policy], {
        'ref': 'missing-resource-tenant',
        'identity': {'ref': 'alice', 'type': 'user', 'role': 'viewer', 'tenant_ref': 'tenant-a', 'scopes': []},
        'resource': {'ref': 'record-1', 'type': 'record', 'tenant_ref': '', 'owner_ref': 'alice'},
        'endpoint': '/bound/record-1',
        'method': 'GET',
        'operation': 'read',
        'response': {'status_code': 403, 'headers': {}, 'body': {'detail': 'Forbidden'}},
    })
    assert missing_tenant['expected_allowed'] is False
    assert missing_tenant['passed'] is True
    assert 'requires both identity and resource tenant bindings' in missing_tenant['reason']

    conditional_policy, _ = persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '/conditional/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'record',
        'allowed': True,
        'ownership_rule': '',
        'tenant_rule': '',
        'sensitive_operation': False,
        'required_scopes': [],
        'conditions': {'mfa': True},
        'policy_source': 'operator_declared',
        'provenance': {'source_ref': 'fixture://conditional'},
        'confidence': 1.0,
        'version': 1,
    })
    unsupported_condition = evaluate_authorization_case([conditional_policy], {
        'ref': 'unsupported-condition',
        'identity': {'ref': 'alice', 'type': 'user', 'role': 'viewer', 'tenant_ref': 'tenant-a', 'scopes': []},
        'resource': {'ref': 'record-2', 'type': 'record', 'tenant_ref': 'tenant-a', 'owner_ref': 'alice'},
        'endpoint': '/conditional/record-2',
        'method': 'GET',
        'operation': 'read',
        'response': {'status_code': 403, 'headers': {}, 'body': {'detail': 'Forbidden'}},
    })
    assert unsupported_condition['expected_allowed'] is False
    assert unsupported_condition['passed'] is True
    assert 'fail-closed' in unsupported_condition['reason']


@pytest.mark.django_db
def test_production_execution_budget_fails_closed_for_destructive_and_over_budget_work():
    user, project = _user_project('execution-budget')
    project.environment = Project.Environment.PRODUCTION
    project.save(update_fields=['environment'])
    budget, created = persist_budget(project, str(user.id), {
        'name': 'production-safe-active',
        'environment': 'production',
        'allowed_capabilities': ['passive', 'safe_active'],
        'max_requests': 100,
        'network_io_bytes': 1_000_000,
        'browser_sessions': 1,
        'identities': 2,
        'object_mutations': 0,
        'parallelism': 2,
        'cpu_seconds': 60,
        'memory_mb': 512,
        'duration_seconds': 120,
        'state_changes': False,
        'destructive_operations': False,
        'state_change_policy': 'deny',
        'version': 1,
    })
    assert created is True

    safe = evaluate_execution_budget(budget, {
        'capabilities': ['safe_active'],
        'requests': 50,
        'parallelism': 2,
        'memory_mb': 256,
        'duration_seconds': 60,
    })
    assert safe['allowed'] is True

    unsafe = evaluate_execution_budget(budget, {
        'capabilities': ['safe_active', 'race'],
        'requests': 101,
        'parallelism': 10,
        'object_mutations': 1,
        'state_changes': True,
        'destructive_operations': True,
    })
    assert unsafe['allowed'] is False
    joined = ' | '.join(unsafe['failures'])
    assert 'requests exceeds budget' in joined
    assert 'destructive operations' in joined
    assert 'state changes' in joined
    assert 'capabilities not allowed' in joined


@pytest.mark.django_db
def test_provider_gate_requires_complete_approval_and_rejects_privileged_runtime():
    user, project = _user_project('provider-gate')
    complete_manifest = {
        'license': {'spdx': 'Apache-2.0', 'reviewed': True},
        'maintenance': {'status': 'active'},
        'sbom': True,
        'supply_chain_integrity': True,
        'known_cves': [],
        'container_privileges': [],
        'network_permissions': ['target-scope-only'],
        'output_quality': {'canonical_adapter': True},
        'determinism': True,
        'evidence_quality': True,
        'ci_reproducibility': True,
    }
    approved, created = persist_provider_approval(project, str(user.id), {
        'provider_name': 'fixture-provider',
        'provider_version': '1.2.3',
        'status': 'approved',
        'capability': 'websocket.discovery',
        'manifest': complete_manifest,
        'rationale': 'CI fixture proving provider gate semantics',
    })
    assert created is True
    assert evaluate_provider_gate(approved, 'websocket.discovery')['allowed'] is True

    restricted, _ = persist_provider_approval(project, str(user.id), {
        'provider_name': 'unsafe-provider',
        'provider_version': '9.9.9',
        'status': 'restricted',
        'capability': 'websocket.discovery',
        'manifest': {
            **complete_manifest,
            'container_privileges': ['privileged', 'docker-socket'],
            'ci_reproducibility': False,
            'unmitigated_critical_cves': ['CVE-2099-0001'],
        },
        'rationale': 'Unsafe fixture',
    })
    result = evaluate_provider_gate(restricted, 'websocket.discovery')
    assert result['allowed'] is False
    joined = ' | '.join(result['failures'])
    assert 'not approved' in joined
    assert 'forbidden container privileges' in joined
    assert 'unmitigated critical CVEs' in joined
    assert 'ci_reproducibility is not proven' in joined
