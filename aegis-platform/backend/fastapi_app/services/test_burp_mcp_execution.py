from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from asgiref.sync import sync_to_async
from django.db import connections
from fastapi import FastAPI
from fastapi.testclient import TestClient

from django_project.assets.models import AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPSession
from enterprise.governed_action_models import EvidenceQualificationEvaluation
from enterprise.provider_approval_models import ProviderApprovalDecision
from enterprise.models import TenantProject
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.routers import capabilities as api
from fastapi_app.services.burp_mcp_gateway import BURP_MCP_CAPABILITY_ID
from fastapi_app.services.provider_approval import record_provider_decision
from fastapi_app.services.test_burp_mcp_gateway import _manifest
from fastapi_app.services.test_burp_mcp_transport import SSEContractServer
from fastapi_app.services.test_web_labs_preparation import context  # noqa: F401
from fastapi_app.services.web_security_foundation import persist_provider_approval
from fastapi_app.services.web_labs_preparation import prepare_web_lab
from fastapi_app.tasks import burp_mcp as worker

pytestmark = pytest.mark.django_db(transaction=True)


def approve(context, endpoint, *, transport='sse', marker='first'):
    user, project, *_ = context
    manifest = _manifest(endpoint)
    if transport == 'sse':
        manifest.update(mcp_transport='sse', mcp_tools={'burp.http_request': 'send_http1_request'})
    manifest['review_marker'] = marker
    persist_provider_approval(project, str(user.id), {
        'provider_name': 'burp-suite-mcp', 'provider_version': '2026.9', 'status': 'approved',
        'capability': BURP_MCP_CAPABILITY_ID, 'manifest': manifest,
        'rationale': 'Synthetic transport test double; not live Burp provenance.',
    })
    return ProviderApprovalDecision.objects.filter(project=project).latest('decision_version')


@pytest.fixture
def client(context, monkeypatch):
    app = FastAPI()
    app.include_router(api.router, prefix='/api/v1/capabilities')
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(context[0].id)}
    dispatches = []

    def dispatch(*, args, queue, routing_key):
        dispatches.append((args, queue, routing_key))
        return SimpleNamespace(id='burp-test-task-' + args[0])

    monkeypatch.setattr(api.run_burp_mcp_probe, 'apply_async', dispatch)
    with TestClient(app) as test_client:
        try:
            yield test_client, dispatches
        finally:
            test_client.portal.call(sync_to_async(connections.close_all, thread_sensitive=True))


def payload(context, decision, **changes):
    value = {'project_id': str(context[1].id), 'asset_id': str(context[2].id),
             'options': {'provider_decision_ref': str(decision.id)},
             'idempotency_key': 'burp-probe-idem-01', 'correlation_id': 'burp-probe-corr-01'}
    value.update(changes)
    return value


def schedule(client, context, decision):
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=payload(context, decision))
    assert response.status_code == 202, response.text
    return Scan.objects.get(pk=response.json()['scan']['id'])


def test_canonical_execution_uses_current_provider_existing_queue_and_replay(client, context):
    with SSEContractServer() as server:
        decision = approve(context, server.endpoint)
        scan = schedule(client, context, decision)
        response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=payload(context, decision))
        assert response.status_code == 202, response.text
        assert response.json()['idempotency_reused'] is True
        assert server.messages == []  # Scheduling cannot open a provider connection.
    assert len(client[1]) == 1
    assert client[1][0] == ([str(scan.id)], api.SCANNER_QUEUE, api.SCANNER_QUEUE)
    assert scan.engines == ['burp-mcp']
    assert scan.execution_contract['runner_profile'] == 'web'
    assert scan.execution_contract['allowed_options']['provider_decision_ref'] == str(decision.id)
    assert scan.authorization_decision_id == context[3].id


@pytest.mark.parametrize('change', ['endpoint', 'content', 'path', 'wrong_lab', 'bad_uuid', 'too_many_secrets'])
def test_client_cannot_supply_raw_request_or_target_or_wrong_lab(client, context, change):
    decision = approve(context, 'http://127.0.0.1:9876/sse')
    body = payload(context, decision)
    if change in {'endpoint', 'content', 'path'}:
        body['options'][change] = 'synthetic-client-input'
    elif change == 'wrong_lab':
        body['options']['lab_definition_id'] = 'other-lab'
    elif change == 'bad_uuid':
        body['options']['provider_decision_ref'] = 'not-a-uuid'
    else:
        body['credential_refs'] = [str(c.id) for c in context[-1]]
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=body)
    assert response.status_code in {400, 409}
    assert Scan.objects.count() == 0
    assert client[1] == []


@pytest.mark.parametrize('change', ['foreign_project', 'stale', 'revoked', 'legacy'])
def test_provider_scope_recency_and_transport_block_scheduling(client, context, change):
    decision = approve(context, 'http://127.0.0.1:9876/sse', transport='legacy' if change == 'legacy' else 'sse')
    if change == 'foreign_project':
        other = Project.objects.create(name='Other', slug='other-burp', owner=context[0])
        TenantProject.objects.create(organization=context[4].organization, project=other)
        record_provider_decision(project_id=str(other.id), actor_id=str(context[0].id),
                                 provider_name=decision.provider_name, provider_version=decision.provider_version,
                                 capability=decision.capability, status='approved', manifest=decision.manifest,
                                 rationale='Other project transport fixture.')
        decision = ProviderApprovalDecision.objects.filter(project=other).latest('decision_version')
    elif change == 'stale':
        approve(context, 'http://127.0.0.1:9876/sse', marker='newer')
    elif change == 'revoked':
        record_provider_decision(project_id=str(context[1].id), actor_id=str(context[0].id),
                                 provider_name=decision.provider_name, provider_version=decision.provider_version,
                                 capability=decision.capability, status='revoked', manifest=decision.manifest,
                                 rationale='Latest decision revoked.')
    response = client[0].post('/api/v1/capabilities/burp.mcp.gateway/execute', json=payload(context, decision))
    assert response.status_code == 409, response.text
    assert Scan.objects.count() == 0
    assert client[1] == []


def allow_test_target(monkeypatch):
    def authorized(scan_id):
        scan = Scan.objects.select_related('authorization_decision').get(pk=scan_id)
        return scan, scan.config['target'], scan.authorization_decision
    monkeypatch.setattr(worker, 'require_bound_scan_authorization', authorized)


def test_worker_persists_qualified_redacted_probe_evidence_without_lab_verdict(client, context, monkeypatch):
    allow_test_target(monkeypatch)  # Unit boundary for DNS/egress only; gateway checks durable grants.
    with SSEContractServer() as server:
        scan = schedule(client, context, approve(context, server.endpoint))
        result = worker.run_burp_mcp_probe.run(str(scan.id))
        assert result['status'] == 'completed', result
        calls = [m for m in server.messages if m['method'] == 'tools/call']
        assert len(calls) == 1
        assert calls[0]['params']['arguments']['targetHostname'] == 'bac-target'
        second = worker.run_burp_mcp_probe.run(str(scan.id))
        assert not second.get('lab_solved')
        assert len([m for m in server.messages if m['method'] == 'tools/call']) == 1
    scan.refresh_from_db()
    invocation = BurpMCPInvocation.objects.get()
    assert BurpMCPSession.objects.count() == 1
    assert EvidenceQualificationEvaluation.objects.filter(pk=invocation.qualification_id).exists()
    evidence = Evidence.objects.get(pk=invocation.evidence_id)
    stored = json.dumps(scan.engine_results) + evidence.raw_output
    assert 'synthetic-private-value' not in stored
    assert 'synthetic-body-private' not in stored
    assert scan.engine_results['burp-mcp']['lab_solved'] is False
    assert scan.engine_results['burp-mcp']['live_fixture_revision_verified'] is False
    assert scan.engine_results['burp-mcp']['finding_ids'] == []


@pytest.mark.parametrize('change', ['config', 'envelope', 'credential_shape', 'authorization', 'provider', 'cancelled', 'paused'])
def test_worker_rechecks_contract_and_current_scope_before_provider_call(client, context, monkeypatch, change):
    allow_test_target(monkeypatch)
    with SSEContractServer() as server:
        decision = approve(context, server.endpoint)
        scan = schedule(client, context, decision)
        if change == 'config':
            scan.config['capability_options']['provider_decision_ref'] = str(uuid4())
        elif change == 'envelope':
            scan.execution_contract['actor_ref'] = 'user:forged'
        elif change == 'credential_shape':
            scan.config['credential_refs'] = {'invalid': 'shape'}
        elif change == 'authorization':
            AssetAuthorization.objects.create(asset=context[2], actor=context[0], authorized=False,
                                              supersedes=context[3], target_snapshot=context[3].target_snapshot)
        elif change == 'provider':
            record_provider_decision(project_id=str(context[1].id), actor_id=str(context[0].id),
                                     provider_name=decision.provider_name, provider_version=decision.provider_version,
                                     capability=decision.capability, status='revoked', manifest=decision.manifest,
                                     rationale='Revoked after scheduling.')
        else:
            scan.status = change
        scan.save()
        result = worker.run_burp_mcp_probe.run(str(scan.id))
        assert result['status'] in {'failed', 'cancelled', 'paused', 'skipped'}, result
        assert server.messages == []
    assert BurpMCPInvocation.objects.count() == 0


def test_preview_exposes_recipe_metadata_and_keeps_solver_unready(context):
    approve(context, 'http://127.0.0.1:9876/sse')
    user, project, asset, _authorization, _membership, credentials = context
    result = prepare_web_lab(actor_id=str(user.id), project_id=str(project.id), asset_id=str(asset.id),
                             lab_definition_id='bac-orders-v1', credential_refs=[str(c.id) for c in credentials],
                             depth='standard')
    assert result['metadata_ready'] is True
    assert result['execution_ready'] is False
    assert next(r for r in result['requirements'] if r['id'] == 'request_operation')['state'] == 'ready'
    assert result['capabilities'][0]['registered'] is True
    assert {'fixture_binding.not_verified', 'runtime.not_checked'} <= {b['code'] for b in result['blockers']}


def test_asset_type_planner_cannot_claim_provider_runtime_readiness():
    from fastapi_app.services.capability_planner import planning_summary
    summary = planning_summary('website')
    probe = next(p for p in summary['plan'] if p['capability_id'] == BURP_MCP_CAPABILITY_ID)
    assert probe['execution_ready'] is False
    assert 'Burp' in probe['reason']
    assert summary['pending_provider_runtime'] == 1


def test_worker_rejects_delivery_on_other_queue(client, context):
    with SSEContractServer() as server:
        scan = schedule(client, context, approve(context, server.endpoint))
        task = worker.run_burp_mcp_probe
        task.push_request(called_directly=False, delivery_info={'routing_key': 'unapproved-queue'})
        try:
            result = task.run(str(scan.id))
        finally:
            task.pop_request()
        assert result['status'] == 'failed'
        assert server.messages == []


@pytest.mark.parametrize('field,value', [('mcp_transport', []), ('mcp_transport', None),
                                        ('mcp_tool_schema_sha256', []), ('mcp_tool_schema_sha256', {'x': 'y'})])
def test_preview_rejects_malformed_transport_metadata_without_server_error(context, field, value):
    user, project, asset, _authorization, _membership, credentials = context
    manifest = _manifest('http://127.0.0.1:9876/sse')
    manifest.update(mcp_transport='sse', mcp_tools={'burp.http_request': 'send_http1_request'})
    manifest[field] = value
    persist_provider_approval(project, str(user.id), {
        'provider_name': 'burp-suite-mcp', 'provider_version': '2026.9', 'status': 'approved',
        'capability': BURP_MCP_CAPABILITY_ID, 'manifest': manifest, 'rationale': 'Malformed metadata test.',
    })
    result = prepare_web_lab(actor_id=str(user.id), project_id=str(project.id), asset_id=str(asset.id),
                             lab_definition_id='bac-orders-v1', credential_refs=[str(c.id) for c in credentials],
                             depth='standard')
    assert result['provider']['state'] == 'invalid_transport'
    assert result['metadata_ready'] is False
    assert result['execution_ready'] is False
