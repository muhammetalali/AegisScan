from __future__ import annotations

import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction

from django_project.assets.models import AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.users.models import User
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPSession
from enterprise.governed_action_models import EvidenceQualificationEvaluation
from enterprise.web_security_models import ProviderApprovalRecord
from fastapi_app.services.burp_mcp_gateway import (
    BURP_MCP_CAPABILITY_ID,
    BurpMCPAuthorizationError,
    BurpMCPConflict,
    BurpMCPProviderError,
    BurpMCPRateLimit,
    invoke_burp_mcp,
    start_burp_mcp_session,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.web_security_foundation import persist_provider_approval


pytestmark = pytest.mark.django_db(transaction=True)


def _manifest(endpoint: str) -> dict:
    return {
        'license': 'commercial-test-license',
        'maintenance': {'status': 'active'},
        'sbom': True,
        'supply_chain_integrity': True,
        'known_cves': [],
        'container_privileges': [],
        'network_permissions': ['authorized-target-only'],
        'output_quality': {'schema': 'mcp-jsonrpc-2.0', 'bounded': True},
        'determinism': True,
        'evidence_quality': True,
        'ci_reproducibility': True,
        'unmitigated_critical_cves': [],
        'mcp_endpoint': endpoint,
        'mcp_tools': {
            'burp.site_map': 'burp_get_site_map',
            'burp.passive_scan': 'burp_passive_scan',
            'burp.active_scan': 'burp_active_scan',
            'burp.issue_details': 'burp_issue_details',
        },
    }


def _approval(project, user, endpoint: str, *, status: str = ProviderApprovalRecord.Status.APPROVED, marker: str = ''):
    manifest = _manifest(endpoint)
    if marker:
        manifest['review_marker'] = marker
    record, _created = persist_provider_approval(
        project,
        str(user.id),
        {
            'provider_name': 'burp-suite-mcp',
            'provider_version': '2026.9',
            'status': status,
            'capability': BURP_MCP_CAPABILITY_ID,
            'manifest': manifest,
            'rationale': 'Governed Burp MCP Reality provider approval.',
        },
    )
    return record


def _session(disposition_fixture, endpoint: str, *, marker: str = 'base', max_invocations: int = 20, rate_limit_per_minute: int = 10):
    _client, user, project, asset, authorization, scan, _finding, _organization, _membership = disposition_fixture
    approval = _approval(project, user, endpoint)
    result = start_burp_mcp_session(
        project_id=str(project.id),
        asset_id=str(asset.id),
        scan_id=str(scan.id),
        authorization_id=str(authorization.id),
        actor_id=str(user.id),
        provider_name='burp-suite-mcp',
        provider_version='2026.9',
        requested_operations=['burp.site_map', 'burp.passive_scan'],
        idempotency_key=f'burp-session-{marker}',
        max_invocations=max_invocations,
        rate_limit_per_minute=rate_limit_per_minute,
        ttl_seconds=600,
    )
    return result, approval


class _MCPHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('content-length') or '0')
        payload = json.loads(self.rfile.read(length).decode('utf-8'))
        type(self).requests.append({
            'path': self.path,
            'payload': payload,
            'authorization_present': bool(self.headers.get('authorization')),
        })
        body = {
            'jsonrpc': '2.0',
            'id': payload.get('id'),
            'result': {
                'items': [
                    {'url': 'https://aegis-disposition-target/', 'status': 200},
                ],
                'secret_token': 'provider-secret-never-store',
                'raw_response_body': 'raw-provider-body-never-store',
                'summary': {'count': 1, 'source': 'burp-reality'},
            },
        }
        encoded = json.dumps(body).encode('utf-8')
        self.send_response(200)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


class _MCPServer:
    def __enter__(self):
        _MCPHandler.requests = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _MCPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.endpoint = f'http://{host}:{port}/mcp'
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def test_burp_session_is_provider_authorization_bound_immutable_and_replay_safe(disposition_fixture, monkeypatch):
    monkeypatch.setenv('BURP_MCP_ALLOW_INSECURE_LOCAL', 'true')
    with _MCPServer() as server:
        first, approval = _session(disposition_fixture, server.endpoint, marker='replay')
        second, _same = _session(disposition_fixture, server.endpoint, marker='replay')

    assert first.replayed is False
    assert second.replayed is True
    assert second.session.id == first.session.id
    session = first.session
    assert session.provider_approval_id == approval.id
    assert session.target_snapshot == 'aegis-disposition-target'
    assert session.allowed_tools['burp.site_map'] == 'burp_get_site_map'
    assert session.contract_snapshot['arbitrary_execution'] is False
    assert session.contract_snapshot['raw_secret_persistence'] is False
    assert len(session.provider_identity_sha256) == 64
    assert len(session.contract_fingerprint) == 64

    with pytest.raises(ValidationError):
        BurpMCPSession.objects.filter(pk=session.id).update(max_invocations=99)
    with pytest.raises(ValidationError):
        session.delete()


def test_unapproved_latest_provider_blocks_gateway_start(disposition_fixture):
    _client, user, project, asset, authorization, scan, *_rest = disposition_fixture
    endpoint = 'https://burp-mcp.example.invalid/mcp'
    _approval(project, user, endpoint, status=ProviderApprovalRecord.Status.APPROVED, marker='approved')
    _approval(project, user, endpoint, status=ProviderApprovalRecord.Status.REJECTED, marker='rejected-later')

    with pytest.raises(BurpMCPProviderError, match='not currently admissible'):
        start_burp_mcp_session(
            project_id=str(project.id),
            asset_id=str(asset.id),
            scan_id=str(scan.id),
            authorization_id=str(authorization.id),
            actor_id=str(user.id),
            provider_name='burp-suite-mcp',
            provider_version='2026.9',
            requested_operations=['burp.site_map'],
            idempotency_key='burp-provider-rejected',
        )

    assert BurpMCPSession.objects.count() == 0


def test_actor_requires_project_access_and_active_tenant_membership(disposition_fixture):
    _client, _owner, project, asset, authorization, scan, _finding, _organization, _membership = disposition_fixture
    outsider = User.objects.create_user(
        email='burp-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Burp',
        last_name='Outsider',
    )
    project.members.add(outsider)
    _approval(project, _owner, 'https://burp-mcp.example.invalid/mcp')

    with pytest.raises(BurpMCPAuthorizationError, match='no active enterprise tenant membership'):
        start_burp_mcp_session(
            project_id=str(project.id),
            asset_id=str(asset.id),
            scan_id=str(scan.id),
            authorization_id=str(authorization.id),
            actor_id=str(outsider.id),
            provider_name='burp-suite-mcp',
            provider_version='2026.9',
            requested_operations=['burp.site_map'],
            idempotency_key='burp-cross-tenant',
        )


def test_real_mcp_jsonrpc_call_creates_qualified_redacted_immutable_evidence(disposition_fixture, monkeypatch):
    monkeypatch.setenv('BURP_MCP_ALLOW_INSECURE_LOCAL', 'true')
    _client, user, _project, _asset, _authorization, _scan, _finding, organization, _membership = disposition_fixture

    with _MCPServer() as server:
        session_result, approval = _session(disposition_fixture, server.endpoint, marker='real-call')
        result = invoke_burp_mcp(
            session_id=str(session_result.session.id),
            actor_id=str(user.id),
            operation='burp.site_map',
            arguments={'path_prefix': '/', 'max_items': 20},
            idempotency_key='burp-invoke-real',
        )

    assert result.replayed is False
    invocation = result.invocation
    evidence = invocation.evidence
    qualification = invocation.qualification

    assert len(_MCPHandler.requests) == 1
    request = _MCPHandler.requests[0]
    assert request['path'] == '/mcp'
    assert request['payload']['jsonrpc'] == '2.0'
    assert request['payload']['method'] == 'tools/call'
    assert request['payload']['params']['name'] == 'burp_get_site_map'
    assert request['payload']['params']['arguments']['target'] == 'aegis-disposition-target'
    assert request['authorization_present'] is False

    assert invocation.session.provider_approval_id == approval.id
    assert invocation.operation == 'burp.site_map'
    assert invocation.provider_tool_name == 'burp_get_site_map'
    assert invocation.result_summary['secret_token'] == '__redacted__'
    assert invocation.result_summary['raw_response_body'] == '__redacted__'
    assert 'provider-secret-never-store' not in json.dumps(invocation.result_summary)
    assert 'raw-provider-body-never-store' not in json.dumps(invocation.result_summary)
    assert len(invocation.provider_result_sha256) == 64

    assert evidence.source == 'burp_mcp'
    assert evidence.evidence_type == 'provider_execution'
    assert evidence.metadata['source_capability'] == BURP_MCP_CAPABILITY_ID
    assert evidence.metadata['organization_id'] == str(organization.id)
    assert evidence.metadata['execution_ref'] == str(invocation.session_id)
    assert evidence.metadata['provider_approval_id'] == str(approval.id)
    assert evidence.metadata['raw_secret_persisted'] is False
    assert hashlib.sha256(evidence.raw_output.encode()).hexdigest() == evidence.sha256
    assert 'provider-secret-never-store' not in evidence.raw_output
    assert 'raw-provider-body-never-store' not in evidence.raw_output

    assert qualification.qualified is True
    assert qualification.decision == EvidenceQualificationEvaluation.Decision.QUALIFIED
    assert qualification.subject_type == 'asset'
    assert qualification.subject_id == str(invocation.session.asset_id)
    assert qualification.authorization_ref == str(invocation.session.authorization_decision_id)
    assert qualification.execution_ref == str(invocation.session_id)

    replay = invoke_burp_mcp(
        session_id=str(invocation.session_id),
        actor_id=str(user.id),
        operation='burp.site_map',
        arguments={'path_prefix': '/', 'max_items': 20},
        idempotency_key='burp-invoke-real',
    )
    assert replay.replayed is True
    assert replay.invocation.id == invocation.id
    assert len(_MCPHandler.requests) == 1

    with pytest.raises(ValidationError):
        BurpMCPInvocation.objects.filter(pk=invocation.id).update(operation='tampered')
    with pytest.raises(ValidationError):
        invocation.delete()

    if connection.vendor == 'postgresql':
        with pytest.raises(DatabaseError, match='Burp MCP evidence is immutable'):
            with transaction.atomic():
                Evidence.objects.filter(pk=evidence.id).update(raw_output='tampered')
        evidence.refresh_from_db()
        assert evidence.raw_output != 'tampered'


def test_authorization_drift_after_session_fails_closed_without_partial_evidence(disposition_fixture, monkeypatch):
    monkeypatch.setenv('BURP_MCP_ALLOW_INSECURE_LOCAL', 'true')
    _client, user, _project, asset, authorization, _scan, *_rest = disposition_fixture
    with _MCPServer() as server:
        session_result, _approval_row = _session(disposition_fixture, server.endpoint, marker='auth-drift')
        AssetAuthorization.objects.create(
            asset=asset,
            actor=user,
            authorized=False,
            target_snapshot=authorization.target_snapshot,
            reason='Revoke Burp MCP authorization before invocation.',
            supersedes=authorization,
        )
        with pytest.raises(BurpMCPAuthorizationError, match='superseded'):
            invoke_burp_mcp(
                session_id=str(session_result.session.id),
                actor_id=str(user.id),
                operation='burp.site_map',
                arguments={'path_prefix': '/'},
                idempotency_key='burp-auth-drift',
            )

    assert BurpMCPInvocation.objects.count() == 0
    assert Evidence.objects.filter(source='burp_mcp').count() == 0
    assert _MCPHandler.requests == []


def test_arbitrary_execution_and_target_escape_are_blocked_before_provider_call(disposition_fixture, monkeypatch):
    monkeypatch.setenv('BURP_MCP_ALLOW_INSECURE_LOCAL', 'true')
    _client, user, *_rest = disposition_fixture
    with _MCPServer() as server:
        session_result, _approval_row = _session(disposition_fixture, server.endpoint, marker='guardrails')
        session_id = str(session_result.session.id)

        with pytest.raises(BurpMCPAuthorizationError, match='not allowlisted'):
            invoke_burp_mcp(
                session_id=session_id,
                actor_id=str(user.id),
                operation='shell.exec',
                arguments={'command': 'id'},
                idempotency_key='burp-shell-block',
            )

        with pytest.raises(BurpMCPAuthorizationError, match='forbidden'):
            invoke_burp_mcp(
                session_id=session_id,
                actor_id=str(user.id),
                operation='burp.site_map',
                arguments={'command': 'id'},
                idempotency_key='burp-command-block',
            )

        with pytest.raises(BurpMCPAuthorizationError, match='escapes the authorized target'):
            invoke_burp_mcp(
                session_id=session_id,
                actor_id=str(user.id),
                operation='burp.passive_scan',
                arguments={'url': 'https://outside.example.invalid/'},
                idempotency_key='burp-target-block',
            )

    assert _MCPHandler.requests == []
    assert Evidence.objects.filter(source='burp_mcp').count() == 0


def test_invocation_budget_fails_closed(disposition_fixture, monkeypatch):
    monkeypatch.setenv('BURP_MCP_ALLOW_INSECURE_LOCAL', 'true')
    _client, user, *_rest = disposition_fixture
    with _MCPServer() as server:
        session_result, _approval_row = _session(
            disposition_fixture,
            server.endpoint,
            marker='budget',
            max_invocations=1,
        )
        session_id = str(session_result.session.id)
        first = invoke_burp_mcp(
            session_id=session_id,
            actor_id=str(user.id),
            operation='burp.site_map',
            arguments={'path_prefix': '/first'},
            idempotency_key='burp-budget-first',
        )
        assert first.replayed is False

        with pytest.raises(BurpMCPRateLimit, match='budget is exhausted'):
            invoke_burp_mcp(
                session_id=session_id,
                actor_id=str(user.id),
                operation='burp.site_map',
                arguments={'path_prefix': '/second'},
                idempotency_key='burp-budget-second',
            )

    assert len(_MCPHandler.requests) == 1
    assert BurpMCPInvocation.objects.count() == 1


def test_burp_api_rejects_unmodeled_arbitrary_fields(disposition_fixture):
    client, user, project, asset, authorization, scan, *_rest = disposition_fixture
    _approval(project, user, 'https://burp-mcp.example.invalid/mcp')

    response = client.post(
        '/api/v1/burp-mcp/sessions',
        json={
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'authorization_id': str(authorization.id),
            'provider_name': 'burp-suite-mcp',
            'provider_version': '2026.9',
            'requested_operations': ['burp.site_map'],
            'idempotency_key': 'burp-api-session',
            'raw_command': 'do-not-accept',
        },
    )
    assert response.status_code == 422

    accepted = client.post(
        '/api/v1/burp-mcp/sessions',
        json={
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'authorization_id': str(authorization.id),
            'provider_name': 'burp-suite-mcp',
            'provider_version': '2026.9',
            'requested_operations': ['burp.site_map'],
            'idempotency_key': 'burp-api-session',
        },
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body['provider_approval_id']
    assert body['allowed_tools']['burp.site_map'] == 'burp_get_site_map'
    assert len(body['contract_fingerprint']) == 64

    invoke_rejected = client.post(
        f"/api/v1/burp-mcp/sessions/{body['id']}/invoke",
        json={
            'operation': 'burp.site_map',
            'arguments': {'path_prefix': '/'},
            'idempotency_key': 'burp-api-invoke',
            'shell': 'id',
        },
    )
    assert invoke_rejected.status_code == 422


def test_conflicting_session_idempotency_fails_closed(disposition_fixture):
    _client, user, project, asset, authorization, scan, *_rest = disposition_fixture
    _approval(project, user, 'https://burp-mcp.example.invalid/mcp')

    first = start_burp_mcp_session(
        project_id=str(project.id),
        asset_id=str(asset.id),
        scan_id=str(scan.id),
        authorization_id=str(authorization.id),
        actor_id=str(user.id),
        provider_name='burp-suite-mcp',
        provider_version='2026.9',
        requested_operations=['burp.site_map'],
        idempotency_key='burp-conflict',
    )
    assert first.replayed is False

    with pytest.raises(BurpMCPConflict, match='different request'):
        start_burp_mcp_session(
            project_id=str(project.id),
            asset_id=str(asset.id),
            scan_id=str(scan.id),
            authorization_id=str(authorization.id),
            actor_id=str(user.id),
            provider_name='burp-suite-mcp',
            provider_version='2026.9',
            requested_operations=['burp.passive_scan'],
            idempotency_key='burp-conflict',
        )
