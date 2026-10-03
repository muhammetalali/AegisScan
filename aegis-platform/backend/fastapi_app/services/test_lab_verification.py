from __future__ import annotations

import importlib.util
import json
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4, uuid5, NAMESPACE_URL

import pytest
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from fastapi.testclient import TestClient

from django_project.evidence.models import Evidence, FindingConfirmation, ValidationRun
from django_project.scans.models import Scan
from django_project.system.credential_vault import CredentialVaultDenied
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPInvocationClaim
from fastapi_app.services import burp_mcp_gateway as gateway, lab_verification as verifier
from fastapi_app.services.burp_lab_requests import VERIFIED_STEPS
from fastapi_app.services.finding_confirmation import confirm_finding
from fastapi_app.services.test_burp_mcp_execution import client, context, approve, payload, allow_test_target  # noqa: F401
from fastapi_app.services.test_burp_lab_execution import tokens
from fastapi_app.tasks import burp_mcp as worker

pytestmark = pytest.mark.django_db(transaction=True)


def inspection(context, *, module=None, variant='vulnerable'):
    return {'target': context[3].target_snapshot, 'instance_ref': module.INSTANCE_REF if module else str(uuid4()),
        'process_ref': module.PROCESS_REF if module else str(uuid4()), 'fixture_revision': verifier.FIXTURE_REVISION,
        'variant': variant, 'image_id': 'sha256:' + 'a' * 64, 'container_id': 'b' * 64, 'inspected_at': time.time()}


def register(context, value=None):
    return verifier.record_runtime_inspection(asset=context[2], actor_id=str(context[0].id),
                                              inspection=value or inspection(context))


def verified_double(monkeypatch, context, *, variant='vulnerable', change=None):
    # Actual fixture handlers, synthetic control-plane inspection and MCP double.
    # The separate live harness proves the inspector and actual Burp transport.
    monkeypatch.setenv('AEGIS_LAB_INSTANCE_REF', str(uuid4()))
    monkeypatch.setenv('AEGIS_LAB_VARIANT', variant)
    path = Path(__file__).resolve().parents[3] / 'e2e/fixtures/bac-target/app.py'
    spec = importlib.util.spec_from_file_location('bac_verification_contract_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.REVISION == verifier.FIXTURE_REVISION
    runtime = register(context, inspection(context, module=module, variant=variant))
    calls = []
    def call(**kw):
        assert not connection.in_atomic_block
        content = kw['request_arguments']['content']; calls.append(content)
        method, path, _ = content.split('\r\n', 1)[0].split(' ')
        headers = dict(line.split(': ', 1) for line in content.split('\r\n')[1:] if ': ' in line)
        with TestClient(module.app) as fixture:
            reply = fixture.request(method, path, headers=headers)
        data = reply.json()
        if change and '__lab__' in path and 'instance_after' in path:
            data[change] = str(uuid4()) if change in {'instance_ref', 'process_ref'} else 'wrong-challenge'
        raw = f'HTTP/1.1 {reply.status_code} Reply\r\nContent-Type: application/json\r\n\r\n' + json.dumps(data)
        wrapped = 'HttpRequestResponse{httpRequest=' + content + ', httpResponse=' + raw + ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        return {'mcp_result': {'content': [{'type': 'text', 'text': wrapped}]},
                'transport_metadata': {'transport': 'contract-double', 'retry_count': 0}}, kw['request_id']
    monkeypatch.setattr(gateway, '_perform_mcp_call', call)
    return runtime, calls


def schedule_verified(client, context, runtime):
    tokens(context)
    decision = approve(context, 'http://127.0.0.1:9876/sse')
    body = payload(context, decision, credential_refs=[str(c.id) for c in context[-1]])
    body['options'].update(mode='verified_lab_sequence', runtime_evidence_ref=str(runtime.id))
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=body)
    assert response.status_code == 202, response.text
    return Scan.objects.get(pk=response.json()['scan']['id'])


def pure_case(variant='vulnerable'):
    session = SimpleNamespace(id=uuid4(), scan_id=uuid4(), asset_id=uuid4())
    runtime = {'instance_ref': str(uuid4()), 'process_ref': str(uuid4()),
               'fixture_revision': verifier.FIXTURE_REVISION, 'variant': variant}
    statuses = [200, 200, 200 if variant == 'vulnerable' else 404, 404, 200, 401, 200, 200]
    alice = {'id': '51', 'owner_id': 'alice', 'tenant_id': 'tenant-a'}
    bob = {'id': '74', 'owner_id': 'bob', 'tenant_id': 'tenant-b'}
    resources = [None, alice, bob if variant == 'vulnerable' else None, None, bob, None, alice, None]
    observations = []
    for (step, (identity, path)), status, resource in zip(VERIFIED_STEPS.items(), statuses, resources):
        o = {'step_ref': step, 'action_ref': 'GET:' + path, 'identity_ref': identity,
             'attempt_ref': str(session.scan_id), 'target_ref': str(session.asset_id),
             'definition_id': 'bac-orders-v1', 'fixture_revision': verifier.FIXTURE_REVISION,
             'status_code': status, 'resource': deepcopy(resource),
             'wire_request_sha256': 'c' * 64, 'response_sha256': 'd' * 64}
        if step.startswith('instance_'):
            o['instance_identity'] = {**runtime, 'nonce': str(session.id) + '-' + step}
        observations.append(o)
    return observations, session, runtime


@pytest.mark.parametrize('variant,expected', [('vulnerable', 'vulnerable'), ('patched', 'not_vulnerable')])
def test_verdict_requires_owner_semantics_and_independent_runtime(variant, expected):
    observations, session, runtime = pure_case(variant)
    result = verifier.evaluate_bac_observations(observations, session=session, runtime=runtime)
    assert result['verdict'] == expected
    assert result['lab_solved'] is (variant == 'vulnerable')
    assert result['live_fixture_revision_verified'] is True


@pytest.mark.parametrize('mutation', ['attempt', 'target', 'revision', 'identity', 'action', 'step',
    'missing', 'duplicate', 'reordered', 'hash', 'baseline', 'recheck', 'bob', 'patched_200',
    'patched_resource', 'anonymous_200', 'anonymous_resource', 'cross_no_resource', 'cross_wrong_owner',
    'cross_wrong_tenant', 'cross_wrong_id', 'instance', 'process', 'challenge', 'boolean_status', 'variant'])
def test_no_solved_verdict_for_missing_mixed_stale_or_conflicting_facts(mutation):
    observations, session, runtime = pure_case()
    if mutation in {'attempt', 'target', 'revision', 'identity', 'action', 'step'}:
        key = {'attempt': 'attempt_ref', 'target': 'target_ref', 'revision': 'fixture_revision',
               'identity': 'identity_ref', 'action': 'action_ref', 'step': 'step_ref'}[mutation]
        observations[2][key] = 'wrong-binding'
    elif mutation == 'missing': observations.pop()
    elif mutation == 'duplicate': observations[3] = deepcopy(observations[2])
    elif mutation == 'reordered': observations[1], observations[2] = observations[2], observations[1]
    elif mutation == 'hash': observations[2]['response_sha256'] = 'not-a-hash'
    elif mutation in {'baseline', 'recheck', 'bob'}:
        observations[{'baseline': 1, 'recheck': 6, 'bob': 4}[mutation]]['resource']['owner_id'] = 'other'
    elif mutation in {'patched_200', 'anonymous_200'}:
        observations[3 if mutation == 'patched_200' else 5]['status_code'] = 200
    elif mutation in {'patched_resource', 'anonymous_resource'}:
        observations[3 if mutation == 'patched_resource' else 5]['resource'] = observations[2]['resource']
    elif mutation == 'cross_no_resource': observations[2]['resource'] = None
    elif mutation.startswith('cross_wrong_'):
        observations[2]['resource'][{'cross_wrong_owner': 'owner_id', 'cross_wrong_tenant': 'tenant_id',
                                     'cross_wrong_id': 'id'}[mutation]] = 'wrong-resource'
    elif mutation in {'instance', 'process', 'challenge'}:
        observations[-1]['instance_identity'][{'instance': 'instance_ref', 'process': 'process_ref',
                                               'challenge': 'nonce'}[mutation]] = 'wrong-binding'
    elif mutation == 'boolean_status': observations[2]['status_code'] = True
    elif mutation == 'variant': runtime['variant'] = 'patched'
    result = verifier.evaluate_bac_observations(observations, session=session, runtime=runtime)
    assert result['verdict'] == 'indeterminate' and result['lab_solved'] is False
    assert result['finding_present'] is None


def test_verified_worker_creates_qualified_validation_and_open_finding_without_self_confirmation(client, context, monkeypatch):
    allow_test_target(monkeypatch)
    runtime, calls = verified_double(monkeypatch, context)
    scan = schedule_verified(client, context, runtime)
    result = worker.run_burp_mcp_probe.run(str(scan.id))
    assert result['status'] == 'completed' and result['lab_solved'] is True, result
    scan.refresh_from_db(); verdict = scan.engine_results['burp-mcp']['lab_verification']
    assert verdict['verdict'] == 'vulnerable' and verdict['live_fixture_revision_verified'] is True
    assert len(calls) == BurpMCPInvocation.objects.count() == BurpMCPInvocationClaim.objects.count() == 8
    finding = Vulnerability.objects.get(pk=verdict['finding_id'])
    validation = ValidationRun.objects.get(pk=verdict['validation_run_id'])
    assert finding.status == 'open' and not FindingConfirmation.objects.exists()
    assert validation.result['finding_present'] is True
    assert verdict['finding_confirmation'] == 'pending_independent_review'
    # Compatibility with the existing confirmation service, using another actor.
    # API responsibility/governance tests remain in test_finding_confirmation.
    reviewer = User.objects.create_user(email='lab-independent-reviewer@example.invalid', password=None)
    confirmed = confirm_finding(finding_id=finding.id, validation_id=validation.id,
        verdict='confirmed', rationale='Reviewed the independent BAC controls.', actor_id=reviewer.id)
    assert confirmed.confirmation.evidence_id == verdict['evidence_id'] or str(confirmed.confirmation.evidence_id) == verdict['evidence_id']
    finding.refresh_from_db(); assert finding.status == 'confirmed'
    assert worker.run_burp_mcp_probe.run(str(scan.id))['status'] in {'completed', 'skipped'}
    assert len(calls) == 8 and Vulnerability.objects.count() == ValidationRun.objects.count() == 1
    persisted = ''.join(Evidence.objects.values_list('raw_output', flat=True)) + json.dumps(scan.engine_results)
    assert all(secret not in persisted for secret in ['alice-token', 'bob-token', 'Authorization:', 'Set-Cookie'])


def test_patched_twin_produces_negative_verdict_and_no_finding(client, context, monkeypatch):
    allow_test_target(monkeypatch)
    runtime, calls = verified_double(monkeypatch, context, variant='patched')
    scan = schedule_verified(client, context, runtime)
    result = worker.run_burp_mcp_probe.run(str(scan.id))
    assert result['status'] == 'completed' and result['lab_solved'] is False, result
    scan.refresh_from_db(); verdict = scan.engine_results['burp-mcp']['lab_verification']
    assert verdict['verdict'] == 'not_vulnerable' and verdict['finding_present'] is False
    assert verdict['live_fixture_revision_verified'] is True and len(calls) == 8
    assert not Vulnerability.objects.exists() and not ValidationRun.objects.exists()


@pytest.mark.parametrize('change', ['instance_ref', 'process_ref', 'nonce'])
def test_runtime_restart_or_wrong_challenge_is_indeterminate(client, context, monkeypatch, change):
    allow_test_target(monkeypatch)
    runtime, calls = verified_double(monkeypatch, context, change=change)
    scan = schedule_verified(client, context, runtime)
    result = worker.run_burp_mcp_probe.run(str(scan.id))
    assert result['status'] == 'completed' and not result['lab_solved'], result
    scan.refresh_from_db()
    assert scan.engine_results['burp-mcp']['lab_verification']['verdict'] == 'indeterminate'
    assert not Vulnerability.objects.exists() and len(calls) == 8


@pytest.mark.parametrize('bad', ['tamper', 'unsigned', 'foreign_project', 'foreign_asset', 'other_origin', 'old', 'key_rotation'])
def test_runtime_proof_signature_scope_age_and_key_cannot_be_bypassed(context, monkeypatch, bad):
    runtime = register(context)
    arguments = dict(evidence_ref=str(runtime.id), project_id=str(context[1].id),
                     asset_id=str(context[2].id), target=context[3].target_snapshot)
    if bad in {'tamper', 'unsigned'}:
        value = json.loads(runtime.raw_output)
        value['signed_inspection'] = value['signed_inspection'][:-5] + 'WRONG' if bad == 'tamper' else 'self-asserted'
        fake = Evidence.objects.create(asset=context[2], source='lab_runtime_inspector',
            evidence_type='lab_runtime_binding', raw_output=json.dumps(value))
        arguments['evidence_ref'] = str(fake.id)
    elif bad == 'foreign_project': arguments['project_id'] = str(uuid4())
    elif bad == 'foreign_asset': arguments['asset_id'] = str(uuid4())
    elif bad == 'other_origin': arguments['target'] = 'http://other.invalid'
    elif bad == 'old':
        now = time.time(); monkeypatch.setattr(verifier.time, 'time', lambda: now + 601)
    elif bad == 'key_rotation': monkeypatch.setenv('AEGIS_EVIDENCE_HMAC_KEY', 'rotated-key-' + 'z' * 48)
    with pytest.raises(CredentialVaultDenied): verifier.validate_runtime_evidence(**arguments)


@pytest.mark.parametrize('source', ['lab_runtime_inspector', 'lab_verification'])
def test_runtime_and_verdict_evidence_are_immutable_in_orm_and_postgresql(context, source):
    row = Evidence.objects.create(asset=context[2], source=source, raw_output='bounded-test-output')
    with pytest.raises(ValidationError): Evidence.objects.filter(pk=row.id).update(raw_output='tampered')
    with pytest.raises(ValidationError): row.delete()
    row.raw_output = 'tampered'
    with pytest.raises(ValidationError): row.save()
    if connection.vendor == 'postgresql':
        with pytest.raises(DatabaseError), transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute('UPDATE evidence_evidence SET raw_output=%s WHERE id=%s', ['tampered', row.id])


def test_duplicate_json_members_cannot_supply_positive_semantics():
    with pytest.raises(ValueError): verifier.strict_json('{"owner_id":"alice","owner_id":"bob"}')


@pytest.mark.parametrize('signature_kind', ['unsigned', 'transplanted'])
def test_forged_verdict_record_cannot_short_circuit_verification(client, context, monkeypatch, signature_kind):
    allow_test_target(monkeypatch)
    runtime, calls = verified_double(monkeypatch, context)
    scan = schedule_verified(client, context, runtime)
    session = gateway.start_burp_mcp_session(project_id=str(context[1].id), asset_id=str(context[2].id),
        scan_id=str(scan.id), authorization_id=str(context[3].id), actor_id=str(context[0].id),
        provider_name='burp-suite-mcp', provider_version='2026.9', requested_operations=['burp.http_request'],
        idempotency_key='poisoned-verdict-test', lab_credential_refs=[str(c.id) for c in context[-1]],
        max_invocations=8, rate_limit_per_minute=60, runtime_evidence_ref=str(runtime.id)).session
    false_result = {'policy_version': verifier.POLICY, 'session_ref': str(uuid4()),
        'attempt_ref': str(uuid4()), 'asset_ref': str(context[2].id),
        'authorization_ref': str(context[3].id), 'verdict': 'vulnerable', 'lab_solved': True}
    raw = verifier.canonical(false_result)
    signature = 'unsigned' if signature_kind == 'unsigned' else verifier._signer(verifier.POLICY).sign_object(verifier.digest(raw))
    Evidence.objects.create(id=uuid5(NAMESPACE_URL, 'aegis:lab-verification:' + str(session.id)),
        scan=scan, asset=context[2], source='lab_verification', raw_output=raw,
        metadata={'trusted_verdict_signature': signature})
    Scan.objects.filter(pk=scan.id).update(status=Scan.Status.RUNNING)
    with pytest.raises(gateway.BurpMCPAuthorizationError, match='integrity'):
        verifier.verify_lab_attempt(session_id=str(session.id), actor_id=str(context[0].id))
    assert not calls and not Vulnerability.objects.exists()
