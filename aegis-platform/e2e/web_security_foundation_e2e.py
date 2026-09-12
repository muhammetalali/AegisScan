#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.web_security_models import SecurityGraphNode, WebSecurityObservation
from fastapi_app.services.web_security_foundation import (
    CONTRACT_VERSION,
    evaluate_negative_invariant,
    persist_policy,
    run_authorization_matrix,
)


BAC_BASE = os.getenv('BAC_TARGET_URL', 'http://127.0.0.1:18081').rstrip('/')
TENANT_BASE = os.getenv('MULTI_TENANT_TARGET_URL', 'http://127.0.0.1:18082').rstrip('/')
EVIDENCE_PATH = Path(
    os.getenv(
        'WEB_SECURITY_E2E_EVIDENCE',
        str(Path(__file__).resolve().parent / 'web-security-foundation-e2e-evidence.json'),
    )
)


def capture(url: str, token: str) -> dict:
    request = Request(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json',
            'User-Agent': 'AegisScan-Web-Security-E2E/2.0',
        },
        method='GET',
    )
    start = time.perf_counter()
    try:
        with urlopen(request, timeout=5) as response:
            status = response.status
            headers = dict(response.headers.items())
            raw = response.read()
    except HTTPError as exc:
        status = exc.code
        headers = dict(exc.headers.items())
        raw = exc.read()
    elapsed = round((time.perf_counter() - start) * 1000.0, 3)
    try:
        body = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        body = {'body_sha256_unavailable': True}
    return {
        'status_code': status,
        'headers': headers,
        'body': body,
        'timing_ms': elapsed,
    }


def case(
    *,
    ref: str,
    identity: dict,
    resource: dict,
    url: str,
    token: str,
    operation: str = 'read',
) -> dict:
    return {
        'ref': ref,
        'identity': identity,
        'resource': resource,
        'endpoint': urlsplit(url).path,
        'method': 'GET',
        'operation': operation,
        'protocol': 'http',
        'response': capture(url, token),
    }


def main() -> int:
    suffix = uuid.uuid4().hex[:12]
    user = User.objects.create_user(
        email=f'web-foundation-e2e-{suffix}@example.invalid',
        password='E2E-Test-Only-Password!42',
        first_name='Web',
        last_name='E2E',
    )
    project = Project.objects.create(
        name=f'Web Security Foundation E2E {suffix}',
        slug=f'web-security-foundation-e2e-{suffix}',
        owner=user,
        environment=Project.Environment.STAGING,
    )

    bac_policy, _ = persist_policy(project, str(user.id), {
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
        'required_scopes': [],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {
            'fixture': 'bac-target',
            'policy_ref': 'e2e://bac/owner-and-tenant-read',
        },
        'confidence': 1.0,
        'version': 1,
    })
    tenant_policy, _ = persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '*/records/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'record',
        'allowed': True,
        'ownership_rule': '',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': [],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {
            'fixture': 'multi-tenant-target',
            'policy_ref': 'e2e://multi-tenant/same-tenant-read',
        },
        'confidence': 1.0,
        'version': 1,
    })

    alice = {
        'ref': 'alice',
        'type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': [],
    }
    service_a = {
        'ref': 'service-a',
        'type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': [],
    }

    cases = [
        case(
            ref='bac-fixed-own-positive',
            identity=alice,
            resource={'ref': 'order-51', 'type': 'order', 'tenant_ref': 'tenant-a', 'owner_ref': 'alice'},
            url=f'{BAC_BASE}/fixed/orders/51',
            token='alice-token',
        ),
        case(
            ref='bac-fixed-cross-tenant-remediated',
            identity=alice,
            resource={'ref': 'order-74', 'type': 'order', 'tenant_ref': 'tenant-b', 'owner_ref': 'bob'},
            url=f'{BAC_BASE}/fixed/orders/74',
            token='alice-token',
        ),
        case(
            ref='bac-vulnerable-cross-tenant-true-positive',
            identity=alice,
            resource={'ref': 'order-74', 'type': 'order', 'tenant_ref': 'tenant-b', 'owner_ref': 'bob'},
            url=f'{BAC_BASE}/vulnerable/orders/74',
            token='alice-token',
        ),
        case(
            ref='tenant-fixed-own-positive',
            identity=service_a,
            resource={'ref': 'record-alpha', 'type': 'record', 'tenant_ref': 'tenant-a', 'owner_ref': ''},
            url=f'{TENANT_BASE}/fixed/tenants/tenant-a/records/alpha',
            token='tenant-a-token',
        ),
        case(
            ref='tenant-fixed-cross-tenant-remediated',
            identity=service_a,
            resource={'ref': 'record-bravo', 'type': 'record', 'tenant_ref': 'tenant-b', 'owner_ref': ''},
            url=f'{TENANT_BASE}/fixed/tenants/tenant-b/records/bravo',
            token='tenant-a-token',
        ),
        case(
            ref='tenant-vulnerable-cross-tenant-true-positive',
            identity=service_a,
            resource={'ref': 'record-bravo', 'type': 'record', 'tenant_ref': 'tenant-b', 'owner_ref': ''},
            url=f'{TENANT_BASE}/vulnerable/tenants/tenant-b/records/bravo',
            token='tenant-a-token',
        ),
    ]

    run, observations = run_authorization_matrix(project, str(user.id), cases)
    by_ref = {item.case_ref: item for item in observations}

    expected_pass = {
        'bac-fixed-own-positive',
        'bac-fixed-cross-tenant-remediated',
        'tenant-fixed-own-positive',
        'tenant-fixed-cross-tenant-remediated',
    }
    expected_fail = {
        'bac-vulnerable-cross-tenant-true-positive',
        'tenant-vulnerable-cross-tenant-true-positive',
    }
    actual_pass = {item.case_ref for item in observations if item.passed}
    actual_fail = {item.case_ref for item in observations if not item.passed}
    if actual_pass != expected_pass:
        raise AssertionError(f'unexpected passing cases: {sorted(actual_pass)}')
    if actual_fail != expected_fail:
        raise AssertionError(f'unexpected failing cases: {sorted(actual_fail)}')
    if run.summary.get('total') != 6 or run.summary.get('passed') != 4 or run.summary.get('failed') != 2:
        raise AssertionError(f'unexpected matrix summary: {run.summary}')
    if run.summary.get('cross_tenant_cases') != 4:
        raise AssertionError(f'unexpected cross-tenant count: {run.summary}')

    for ref in expected_fail:
        item = by_ref[ref]
        if item.expected_allowed is not False or item.observed_decision != 'allowed':
            raise AssertionError(f'{ref} did not prove unauthorized access')
        if len(item.evidence_fingerprint or '') != 64:
            raise AssertionError(f'{ref} missing deterministic evidence fingerprint')

    for ref in {
        'bac-fixed-cross-tenant-remediated',
        'tenant-fixed-cross-tenant-remediated',
    }:
        item = by_ref[ref]
        if item.expected_allowed is not False or item.observed_decision != 'denied' or item.passed is not True:
            raise AssertionError(f'{ref} did not prove remediated isolation')

    negative = evaluate_negative_invariant({
        'ref': 'cross-tenant-must-not-observe',
        'type': 'deny_access',
        'response': cases[4]['response'],
    })
    if not negative['passed']:
        raise AssertionError(f'negative-path invariant failed for fixed target: {negative}')

    node_kinds = set(
        SecurityGraphNode.objects.filter(project=project).values_list('kind', flat=True)
    )
    required_kinds = {'identity', 'tenant', 'resource', 'endpoint', 'policy'}
    if not required_kinds.issubset(node_kinds):
        raise AssertionError(f'identity/object/tenant graph incomplete: {sorted(node_kinds)}')

    persisted = WebSecurityObservation.objects.filter(run=run).count()
    if persisted != 6:
        raise AssertionError(f'expected 6 persisted observations, got {persisted}')

    evidence = {
        'schema': 'aegis.web-security-foundation-e2e.v1',
        'contract_version': CONTRACT_VERSION,
        'project_id': str(project.id),
        'validation_run_id': str(run.id),
        'validation_input_sha256': run.input_sha256,
        'authorization_policy_sha256': [
            bac_policy.canonical_sha256,
            tenant_policy.canonical_sha256,
        ],
        'summary': run.summary,
        'proofs': {
            'true_positive_vulnerable_cases': sorted(expected_fail),
            'true_negative_and_fixed_cases': sorted(expected_pass),
            'cross_tenant_isolation_fixed': [
                'bac-fixed-cross-tenant-remediated',
                'tenant-fixed-cross-tenant-remediated',
            ],
            'negative_invariant_passed': negative['passed'],
            'identity_object_tenant_graph_kinds': sorted(node_kinds),
            'persisted_observation_count': persisted,
        },
        'observations': [
            {
                'id': str(item.id),
                'case_ref': item.case_ref,
                'policy_id': str(item.policy_id) if item.policy_id else None,
                'expected_allowed': item.expected_allowed,
                'observed_decision': item.observed_decision,
                'passed': item.passed,
                'evidence_fingerprint': item.evidence_fingerprint,
                'tenant_ref': item.tenant_ref,
                'resource_tenant_ref': item.resource_tenant_ref,
            }
            for item in observations
        ],
    }
    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({
        'status': 'PASS',
        'run_id': str(run.id),
        'summary': run.summary,
        'evidence_path': str(EVIDENCE_PATH),
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        raise
