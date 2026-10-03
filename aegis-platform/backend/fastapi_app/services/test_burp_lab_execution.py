from __future__ import annotations

import importlib.util
import json
import threading
import time
from pathlib import Path
from uuid import uuid4

import pytest
from django.db import connection, connections, transaction
from fastapi.testclient import TestClient

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan, ScanLog
from django_project.system.credential_vault import encrypt_secret, credential_fingerprint, CredentialVaultDenied, rotate_credential_secret
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPInvocationClaim, BurpMCPSession
from fastapi_app.services import burp_mcp_gateway as gateway
from fastapi_app.services.burp_lab_requests import STEPS, lab_request, summarize_lab_result
from fastapi_app.services.burp_mcp_transport import MCPTransportError, call_burp_sse
from fastapi_app.services.test_burp_mcp_transport import SSEContractServer
from fastapi_app.services.test_burp_mcp_execution import client, context, approve, payload, allow_test_target  # noqa: F401
from fastapi_app.tasks import burp_mcp as worker

pytestmark = pytest.mark.django_db(transaction=True)


def tokens(context):
    for credential in context[-1]:
        token = credential.scope['browser_identity_ref'] + '-token'
        credential.encrypted_secret = encrypt_secret(token)
        credential.secret_fingerprint = credential_fingerprint(token)
        credential.save(update_fields=['encrypted_secret', 'secret_fingerprint'])


def schedule_lab(client, context, **changes):
    tokens(context)
    decision = approve(context, 'http://127.0.0.1:9876/sse')
    body = payload(context, decision, credential_refs=[str(c.id) for c in context[-1]])
    body['options']['mode'] = 'lab_sequence'
    body.update(changes)
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=body)
    assert response.status_code == 202, response.text
    return Scan.objects.get(pk=response.json()['scan']['id']), decision


def lab_session(client, context):
    scan, decision = schedule_lab(client, context)
    result = gateway.start_burp_mcp_session(project_id=str(context[1].id), asset_id=str(context[2].id),
        scan_id=str(scan.id), authorization_id=str(context[3].id), actor_id=str(context[0].id),
        provider_name=decision.provider_name, provider_version=decision.provider_version,
        requested_operations=['burp.http_request'], idempotency_key='lab-session-test',
        lab_credential_refs=[str(c.id) for c in context[-1]], max_invocations=6, rate_limit_per_minute=60)
    return result.session


def invoke(session, context, step='owner_baseline', key='step-test'):
    return gateway.invoke_burp_mcp(session_id=str(session.id), actor_id=str(context[0].id),
        operation='burp.http_request', arguments={'lab_step': step}, idempotency_key=key)


def fixture_double(monkeypatch):
    # Actual pinned fixture routes, in-process HTTP. This is not a live Burp test.
    path = Path(__file__).resolve().parents[3] / 'e2e/fixtures/bac-target/app.py'
    spec = importlib.util.spec_from_file_location('bac_recipe_contract_fixture', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    def call(**kw):
        assert not connection.in_atomic_block
        arguments = kw['request_arguments']
        content = arguments['content']
        calls.append(content)
        method, path, _ = content.split('\r\n', 1)[0].split(' ')
        headers = dict(line.split(': ', 1) for line in content.split('\r\n')[1:] if ': ' in line)
        with TestClient(module.app) as fixture:
            reply = fixture.request(method, path, headers=headers)
        raw = f'HTTP/1.1 {reply.status_code} Reply\r\nContent-Type: application/json\r\nSet-Cookie: do-not-copy\r\n\r\n' + reply.text
        wrapped = 'HttpRequestResponse{httpRequest=' + content + ', httpResponse=' + raw + ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        return {'mcp_result': {'content': [{'type': 'text', 'text': wrapped}]},
                'transport_metadata': {'transport': 'contract-double', 'retry_count': 0}}, kw['request_id']
    monkeypatch.setattr(gateway, '_perform_mcp_call', call)
    return calls


def test_recipe_dispatch_two_identities_and_semantics_with_qualified_redacted_evidence(client, context, monkeypatch):
    scan, _ = schedule_lab(client, context)
    allow_test_target(monkeypatch)
    calls = fixture_double(monkeypatch)
    result = worker.run_burp_mcp_probe.run(str(scan.id))
    assert result['status'] == 'completed', result
    assert result['recipe_executed'] is True
    assert result['lab_solved'] is False
    assert len(calls) == 6
    assert ['Bearer alice-token' in c for c in calls] == [True, True, True, False, False, True]
    assert ['Bearer bob-token' in c for c in calls] == [False, False, False, True, False, False]
    assert 'Authorization:' not in calls[4]
    assert all('do-not-copy' not in c for c in calls)
    scan.refresh_from_db()
    observations = scan.engine_results['burp-mcp']['observations']
    assert [o['status_code'] for o in observations] == [200, 200, 404, 200, 401, 200]
    assert observations[0]['resource']['owner_id'] == 'alice'
    assert observations[1]['resource'] == {'id': '74', 'owner_id': 'bob', 'tenant_id': 'tenant-b'}
    assert observations[2]['resource'] is None
    assert observations[3]['identity_ref'] == 'bob'
    assert observations[-1]['resource']['owner_id'] == 'alice'
    assert BurpMCPInvocationClaim.objects.filter(state='committed').count() == 6
    assert BurpMCPInvocation.objects.count() == 6
    assert all(i.qualification.qualified for i in BurpMCPInvocation.objects.all())
    persisted = json.dumps(scan.engine_results) + ''.join(Evidence.objects.values_list('raw_output', flat=True))
    persisted += json.dumps(list(ScanLog.objects.values_list('context', flat=True)))
    for forbidden in ['alice-token', 'bob-token', 'Authorization:', 'Set-Cookie', 'do-not-copy']:
        assert forbidden not in persisted
    assert worker.run_burp_mcp_probe.run(str(scan.id))['status'] in {'completed', 'skipped'}
    assert len(calls) == 6


@pytest.mark.parametrize('change', ['foreign', 'origin', 'identity', 'duplicate', 'provider_overlap'])
def test_invalid_target_identity_bindings_block_dispatch(client, context, change):
    tokens(context)
    decision = approve(context, 'http://127.0.0.1:9876/sse')
    refs = [str(c.id) for c in context[-1]]
    if change == 'foreign':
        refs[1] = str(uuid4())
    elif change in {'origin', 'identity'}:
        credential = context[-1][1]
        credential.scope['browser_origin' if change == 'origin' else 'browser_identity_ref'] = 'https://other.invalid' if change == 'origin' else 'alice'
        credential.save(update_fields=['scope'])
    elif change == 'duplicate':
        refs[1] = refs[0]
    body = payload(context, decision, credential_refs=refs)
    body['options']['mode'] = 'lab_sequence'
    if change == 'provider_overlap':
        body['options']['provider_credential_ref'] = refs[0]
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=body)
    assert response.status_code in {400, 403, 409}
    assert Scan.objects.count() == 0
    assert client[1] == []


def test_committed_reconciliation_returns_same_evidence_without_second_external_call(client, context, monkeypatch):
    session = lab_session(client, context)
    calls = fixture_double(monkeypatch)
    first = invoke(session, context)
    replay = invoke(session, context)
    assert replay.replayed and first.invocation.id == replay.invocation.id
    assert len(calls) == 1
    with pytest.raises(gateway.BurpMCPConflict):
        invoke(session, context, step='owner_recheck')
    assert len(calls) == 1


def test_lost_response_persists_indeterminate_claim_and_consumes_budget(client, context, monkeypatch):
    session = lab_session(client, context)
    calls = []
    def lost(**kw):
        assert not connection.in_atomic_block
        calls.append(kw['request_id'])
        raise gateway.BurpMCPProviderError('Response lost after possible target execution.')
    monkeypatch.setattr(gateway, '_perform_mcp_call', lost)
    with pytest.raises(gateway.BurpMCPProviderError):
        invoke(session, context)
    claim = BurpMCPInvocationClaim.objects.get()
    assert claim.state == 'indeterminate'
    with pytest.raises(gateway.BurpMCPConflict):
        invoke(session, context)
    assert len(calls) == 1
    assert not Evidence.objects.exists()


def test_crash_left_inflight_claim_is_not_reclaimed_or_sent_again(client, context, monkeypatch):
    session = lab_session(client, context)
    def crash(**kw):
        raise SystemExit('simulate worker death after send')
    monkeypatch.setattr(gateway, '_perform_mcp_call', crash)
    with pytest.raises(SystemExit):
        invoke(session, context)
    assert BurpMCPInvocationClaim.objects.get().state == 'in_flight'
    with pytest.raises(gateway.BurpMCPConflict):
        invoke(session, context)


def test_cancellation_can_update_scan_during_network_and_prevents_evidence_commit(client, context, monkeypatch):
    session = lab_session(client, context)
    original = fixture_double(monkeypatch)
    call = gateway._perform_mcp_call
    def cancel(**kw):
        errors = []
        def update():
            try:
                if connection.vendor == 'postgresql':
                    with connection.cursor() as cursor:
                        cursor.execute("SET lock_timeout = '1s'")
                Scan.objects.filter(pk=session.scan_id).update(status=Scan.Status.CANCELLED)
            except Exception as exc:
                errors.append(exc)
            finally:
                connections.close_all()
        thread = threading.Thread(target=update)
        thread.start(); thread.join(2)
        assert not thread.is_alive() and not errors
        return call(**kw)
    monkeypatch.setattr(gateway, '_perform_mcp_call', cancel)
    with pytest.raises(gateway.BurpMCPAuthorizationError):
        invoke(session, context)
    assert len(original) == 1
    assert not Evidence.objects.exists()
    assert BurpMCPInvocationClaim.objects.get().state == 'indeterminate'


def test_sse_cancels_locally_while_provider_response_is_outstanding():
    stopped = threading.Event()
    with SSEContractServer('timeout') as server:
        def stop_after_call():
            limit = time.monotonic() + 3
            while time.monotonic() < limit and not any(m['method'] == 'tools/call' for m in server.messages):
                time.sleep(0.01)
            stopped.set()
        thread = threading.Thread(target=stop_after_call); thread.start()
        start = time.monotonic()
        with pytest.raises(MCPTransportError, match='execution_cancelled'):
            call_burp_sse(endpoint=server.endpoint, provider_tool_name='send_http1_request', request_id='cancel-test',
                arguments={'content': 'GET /health HTTP/1.1\r\n\r\n', 'targetHostname': 'localhost', 'targetPort': 18081, 'usesHttps': False},
                deadline_seconds=10, cancel_check=stopped.is_set)
        thread.join(3)
        assert time.monotonic() - start < 4
        assert len([m for m in server.messages if m['method'] == 'tools/call']) == 1


def test_rotated_target_credential_invalidates_bound_session_before_request(client, context, monkeypatch):
    session = lab_session(client, context)
    calls = fixture_double(monkeypatch)
    rotate_credential_secret(credential=context[-1][0], actor=context[0], secret='rotated-token')
    with pytest.raises(CredentialVaultDenied):
        invoke(session, context)
    assert not calls and not BurpMCPInvocationClaim.objects.exists()


@pytest.mark.parametrize('arguments', [{'lab_step': 'unknown'}, {'lab_step': []}, {'lab_step': {}}, {'lab_step': 'owner_baseline', 'path': '/health'},
                                      {'lab_step': 'owner_baseline', 'headers': {'Authorization': 'raw'}},
                                      {'path': '/vulnerable/orders/74'}])
def test_gateway_never_accepts_client_raw_request_or_route(client, context, arguments):
    session = lab_session(client, context)
    with pytest.raises(gateway.BurpMCPError):
        gateway.invoke_burp_mcp(session_id=str(session.id), actor_id=str(context[0].id), operation='burp.http_request',
                                arguments=arguments, idempotency_key='invalid-step')
    assert not BurpMCPInvocationClaim.objects.exists()


def test_caller_transaction_cannot_span_external_request(client, context):
    session = lab_session(client, context)
    with transaction.atomic(), pytest.raises(gateway.BurpMCPConflict, match='caller transaction'):
        invoke(session, context)


def test_recipe_budget_counts_unresolved_calls(client, context, monkeypatch):
    session = lab_session(client, context)
    fixture_double(monkeypatch)
    for i, step in enumerate(STEPS):
        invoke(session, context, step=step, key='budget-' + str(i))
    with pytest.raises(gateway.BurpMCPRateLimit):
        invoke(session, context, key='budget-extra')


def test_wrapper_mismatch_and_arbitrary_resource_fields_cannot_become_evidence(client, context):
    session = lab_session(client, context)
    arguments, _ = lab_request(session=session, actor_id=str(context[0].id), step='owner_baseline')
    payload = {'mcp_result': {'content': [{'type': 'text', 'text': 'HttpRequestResponse{httpRequest=wrong, httpResponse=x}'}]}, 'transport_metadata': {}}
    with pytest.raises(ValueError):
        summarize_lab_result(payload, request_arguments=arguments, session=session, step='owner_baseline')
    payload['mcp_result']['content'][0]['text'] = 'HTTP/1.1 200 OK\r\n\r\n' + json.dumps({'id': '51', 'owner_id': 'alice-token', 'tenant_id': 'tenant-a'})
    result = summarize_lab_result(payload, request_arguments=arguments, session=session, step='owner_baseline')
    assert result['resource'] is None and 'alice-token' not in json.dumps(result)


@pytest.mark.parametrize('state', [Scan.Status.COMPLETED, Scan.Status.FAILED])
def test_terminal_scan_reconciles_committed_key_but_cannot_send_new_request(client, context, monkeypatch, state):
    session = lab_session(client, context)
    calls = fixture_double(monkeypatch)
    first = invoke(session, context)
    Scan.objects.filter(pk=session.scan_id).update(status=state)
    assert invoke(session, context).invocation.evidence_id == first.invocation.evidence_id
    with pytest.raises(gateway.BurpMCPAuthorizationError):
        invoke(session, context, step='owner_recheck', key='new-after-terminal')
    assert len(calls) == 1 and BurpMCPInvocationClaim.objects.count() == 1


def test_deactivated_actor_cannot_send_new_request(client, context, monkeypatch):
    session = lab_session(client, context)
    calls = fixture_double(monkeypatch)
    actor = context[0]
    actor.is_active = False
    actor.save(update_fields=['is_active'])
    with pytest.raises(gateway.BurpMCPAuthorizationError):
        invoke(session, context)
    assert not calls and not BurpMCPInvocationClaim.objects.exists()


@pytest.mark.parametrize('during_call', [False, True])
def test_provider_credential_rotation_cannot_cross_claim_or_commit(client, context, monkeypatch, during_call):
    from django_project.system.credential_models import CredentialSecret
    scan, _decision = schedule_lab(client, context)
    provider = CredentialSecret.objects.create(
        project=context[1], created_by=context[0], name='provider authentication',
        kind=CredentialSecret.Kind.API_KEY, encrypted_secret=encrypt_secret('provider-token'),
        secret_fingerprint=credential_fingerprint('provider-token'),
        scope={'burp_provider_name': 'burp-suite-mcp', 'burp_provider_version': '2026.9'})
    session = gateway.start_burp_mcp_session(
        project_id=str(context[1].id), asset_id=str(context[2].id), scan_id=str(scan.id),
        authorization_id=str(context[3].id), actor_id=str(context[0].id),
        provider_name='burp-suite-mcp', provider_version='2026.9',
        requested_operations=['burp.http_request'], idempotency_key='provider-version-session',
        credential_ref=str(provider.id), lab_credential_refs=[str(c.id) for c in context[-1]],
        max_invocations=6, rate_limit_per_minute=60).session
    calls = fixture_double(monkeypatch)
    original = gateway._perform_mcp_call
    def rotate():
        rotate_credential_secret(credential=provider, actor=context[0], secret='rotated-provider-token')
    if during_call:
        def call(**kw):
            assert kw['bearer_token'] == 'provider-token'
            assert 'provider-token' not in kw['request_arguments']['content']
            result = original(**kw)
            rotate()
            return result
        monkeypatch.setattr(gateway, '_perform_mcp_call', call)
    else:
        rotate()
    with pytest.raises(gateway.BurpMCPAuthorizationError, match='provider credential version'):
        invoke(session, context)
    assert len(calls) == int(during_call)
    assert not BurpMCPInvocation.objects.exists()
    if during_call:
        assert BurpMCPInvocationClaim.objects.get().state == 'indeterminate'
        with pytest.raises(gateway.BurpMCPError):
            invoke(session, context, step='owner_recheck', key='other-key-after-unknown')
        assert len(calls) == 1
    else:
        assert not BurpMCPInvocationClaim.objects.exists()
