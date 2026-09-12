from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from django_project.projects.models import Project, ProjectMembership
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import create_credential_secret
from django_project.users.models import User
from fastapi_app.contracts.web_security_v2 import (
    AuthorizationMatrixIn,
    AuthorizationPolicyIn,
    CrossProtocolTransitionBatchIn,
    ExecutionBudgetIn,
    GraphQLSecurityBatchIn,
    GraphSnapshotIn,
    NegativePathBatchIn,
    ProviderApprovalIn,
    ResponseComparisonIn,
    WebSocketSecurityBatchIn,
)
from fastapi_app.core.security import create_access_token
from fastapi_app.main import app
from fastapi_app.routers.web_security import (
    _project_admin_for_user_sync,
    _project_for_user_sync,
    _project_security_operator_for_user_sync,
)


EXPECTED_WEB_SECURITY_ROUTES = {
    '/api/v1/web-security/contract',
    '/api/v1/web-security/projects/{project_id}/graph/snapshot',
    '/api/v1/web-security/projects/{project_id}/graph',
    '/api/v1/web-security/projects/{project_id}/authorization/policies',
    '/api/v1/web-security/projects/{project_id}/authorization/evaluate',
    '/api/v1/web-security/projects/{project_id}/responses/compare',
    '/api/v1/web-security/projects/{project_id}/negative-path/evaluate',
    '/api/v1/web-security/projects/{project_id}/execution-budgets',
    '/api/v1/web-security/projects/{project_id}/execution-budgets/{budget_id}/evaluate',
    '/api/v1/web-security/projects/{project_id}/providers/approvals',
    '/api/v1/web-security/projects/{project_id}/providers/evaluate',
    '/api/v1/web-security/projects/{project_id}/protocols/websocket/evaluate',
    '/api/v1/web-security/projects/{project_id}/protocols/graphql/evaluate',
    '/api/v1/web-security/projects/{project_id}/protocols/cross-protocol/evaluate',
}


def _user(prefix: str) -> User:
    suffix = uuid.uuid4().hex[:10]
    return User.objects.create_user(
        email=f'{prefix}-{suffix}@example.com',
        password='Router-Test-Only-Password!42',
        first_name='Router',
        last_name='Fixture',
    )


def test_web_security_v2_routes_are_registered():
    paths = set(app.openapi().get('paths', {}))
    missing = sorted(EXPECTED_WEB_SECURITY_ROUTES - paths)
    assert not missing, f'Missing Web Security v2 routes: {missing}'


@pytest.mark.parametrize(
    'model',
    [
        AuthorizationPolicyIn,
        ExecutionBudgetIn,
        ProviderApprovalIn,
        GraphSnapshotIn,
        AuthorizationMatrixIn,
        NegativePathBatchIn,
        ResponseComparisonIn,
        WebSocketSecurityBatchIn,
        GraphQLSecurityBatchIn,
        CrossProtocolTransitionBatchIn,
    ],
)
def test_web_security_v2_contracts_reject_unknown_fields(model):
    schema = model.model_json_schema()
    assert schema['additionalProperties'] is False


@pytest.mark.django_db
def test_web_security_project_admin_boundary_is_not_equivalent_to_project_read_access():
    owner = _user('web-owner')
    admin = _user('web-admin')
    viewer = _user('web-viewer')
    analyst = _user('web-analyst')
    analyst.role = 'security_analyst'
    analyst.save(update_fields=['role'])
    outsider = _user('web-outsider')
    project = Project.objects.create(
        name='Web Security Router Boundary',
        slug=f'web-router-{uuid.uuid4().hex[:10]}',
        owner=owner,
    )
    ProjectMembership.objects.create(
        project=project,
        user=admin,
        role=ProjectMembership.Role.ADMIN,
    )
    ProjectMembership.objects.create(
        project=project,
        user=viewer,
        role=ProjectMembership.Role.VIEWER,
    )
    ProjectMembership.objects.create(
        project=project,
        user=analyst,
        role=ProjectMembership.Role.MEMBER,
    )

    assert _project_for_user_sync(str(project.id), str(owner.id)) == project
    assert _project_for_user_sync(str(project.id), str(admin.id)) == project
    assert _project_for_user_sync(str(project.id), str(viewer.id)) == project
    assert _project_for_user_sync(str(project.id), str(analyst.id)) == project
    assert _project_for_user_sync(str(project.id), str(outsider.id)) is None

    assert _project_admin_for_user_sync(str(project.id), str(owner.id)) == project
    assert _project_admin_for_user_sync(str(project.id), str(admin.id)) == project
    assert _project_admin_for_user_sync(str(project.id), str(viewer.id)) is None
    assert _project_admin_for_user_sync(str(project.id), str(outsider.id)) is None

    assert _project_security_operator_for_user_sync(str(project.id), str(owner.id)) == project
    assert _project_security_operator_for_user_sync(str(project.id), str(admin.id)) == project
    assert _project_security_operator_for_user_sync(str(project.id), str(analyst.id)) == project
    assert _project_security_operator_for_user_sync(str(project.id), str(viewer.id)) is None
    assert _project_security_operator_for_user_sync(str(project.id), str(outsider.id)) is None


@pytest.mark.django_db(transaction=True)
def test_web_security_http_api_persists_policy_validation_and_blocks_viewer_writes():
    owner = _user('web-http-owner')
    viewer = _user('web-http-viewer')
    project = Project.objects.create(
        name='Web Security HTTP Integration',
        slug=f'web-http-{uuid.uuid4().hex[:10]}',
        owner=owner,
    )
    ProjectMembership.objects.create(
        project=project,
        user=viewer,
        role=ProjectMembership.Role.VIEWER,
    )
    client = TestClient(app)
    owner_headers = {'Authorization': f'Bearer {create_access_token({"user_id": str(owner.id)})}'}
    viewer_headers = {'Authorization': f'Bearer {create_access_token({"user_id": str(viewer.id)})}'}

    policy_response = client.post(
        f'/api/v1/web-security/projects/{project.id}/authorization/policies',
        headers=owner_headers,
        json={
            'identity_type': 'user',
            'role': 'viewer',
            'tenant_ref': '*',
            'endpoint': '/orders/*',
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
            'provenance': {'source_ref': 'test://http-api'},
            'confidence': 1.0,
            'version': 1,
        },
    )
    assert policy_response.status_code == 201, policy_response.text
    assert policy_response.json()['created'] is True
    assert len(policy_response.json()['canonical_sha256']) == 64

    validation_response = client.post(
        f'/api/v1/web-security/projects/{project.id}/authorization/evaluate',
        headers=owner_headers,
        json={
            'cases': [{
                'ref': 'http-owner-read',
                'identity': {
                    'ref': 'alice',
                    'type': 'user',
                    'role': 'viewer',
                    'tenant_ref': 'tenant-a',
                    'scopes': [],
                },
                'resource': {
                    'ref': 'order-51',
                    'type': 'order',
                    'tenant_ref': 'tenant-a',
                    'owner_ref': 'alice',
                },
                'endpoint': '/orders/51',
                'method': 'GET',
                'operation': 'read',
                'protocol': 'https',
                'response': {
                    'status_code': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': {'id': 51, 'tenant_id': 'tenant-a', 'owner_id': 'alice'},
                    'timing_ms': 12.5,
                },
            }],
        },
    )
    assert validation_response.status_code == 200, validation_response.text
    payload = validation_response.json()
    assert payload['summary'] == {'total': 1, 'passed': 1, 'failed': 0, 'cross_tenant_cases': 0}
    assert payload['observations'][0]['passed'] is True
    assert len(payload['observations'][0]['evidence_fingerprint']) == 64

    graph_response = client.get(
        f'/api/v1/web-security/projects/{project.id}/graph',
        headers=owner_headers,
    )
    assert graph_response.status_code == 200
    assert {'identity', 'tenant', 'resource', 'endpoint', 'policy'}.issubset(
        {node['kind'] for node in graph_response.json()['nodes']}
    )

    viewer_write = client.post(
        f'/api/v1/web-security/projects/{project.id}/graph/snapshot',
        headers=viewer_headers,
        json={
            'nodes': [{
                'plane': 'application',
                'kind': 'endpoint',
                'external_ref': 'endpoint:viewer-poison',
                'label': 'viewer-poison',
                'properties': {},
                'provenance': {'source': 'untrusted-viewer'},
            }],
            'edges': [],
        },
    )
    assert viewer_write.status_code == 403
    assert viewer_write.json()['detail'] == 'Project security-operator authority required'


@pytest.mark.django_db(transaction=True)
def test_protocol_validation_api_persists_websocket_graphql_and_transition_lineage():
    owner = _user('protocol-http-owner')
    project = Project.objects.create(
        name='Protocol Security HTTP Integration',
        slug=f'protocol-http-{uuid.uuid4().hex[:10]}',
        owner=owner,
    )
    client = TestClient(app)
    headers = {'Authorization': f'Bearer {create_access_token({"user_id": str(owner.id)})}'}
    protocol_secret = 'protocol-api-test-secret-only'
    credential = create_credential_secret(
        project=project,
        actor=owner,
        name=f'protocol-api-{uuid.uuid4().hex[:8]}',
        kind=CredentialSecret.Kind.TOKEN,
        secret=protocol_secret,
        scope={
            'protocol_origin': 'https://app.example',
            'protocol_identity_ref': 'alice',
        },
    )
    identity = {
        'ref': 'alice',
        'type': 'user',
        'credential_ref': str(credential.id),
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': ['records:read'],
    }
    resource = {
        'ref': 'record-a',
        'type': 'record',
        'tenant_ref': 'tenant-a',
        'owner_ref': 'alice',
    }
    budget = client.post(
        f'/api/v1/web-security/projects/{project.id}/execution-budgets',
        headers=headers,
        json={
            'name': 'protocol-security-test',
            'environment': 'staging',
            'allowed_capabilities': [
                'websocket_security',
                'graphql_security',
                'cross_protocol_state',
            ],
            'max_requests': 10,
            'network_io_bytes': 1048576,
            'browser_sessions': 0,
            'identities': 2,
            'object_mutations': 0,
            'parallelism': 1,
            'cpu_seconds': 30,
            'memory_mb': 128,
            'duration_seconds': 60,
            'state_changes': False,
            'destructive_operations': False,
            'state_change_policy': 'deny',
            'version': 1,
        },
    )
    assert budget.status_code == 201, budget.text
    budget_id = budget.json()['id']

    ws = client.post(
        f'/api/v1/web-security/projects/{project.id}/protocols/websocket/evaluate',
        headers=headers,
        json={'budget_id': budget_id, 'target_origin': 'https://app.example', 'cases': [{
            'ref': 'ws-own',
            'identity': identity,
            'resource': resource,
            'channel': 'ws://fixture/ws/tenant-a/record-a',
            'session_ref': 'session-a',
            'origin': 'https://app.example',
            'allowed_origins': ['https://app.example'],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'subscribe',
            'expected_allowed': True,
            'server_accepted': True,
            'handshake_status': 101,
            'subscription_owner_ref': 'alice',
            'subscription_tenant_ref': 'tenant-a',
            'reconnect': False,
            'reconnect_reauthenticated': False,
            'message_schema_valid': True,
            'message_authorized': True,
            'binary': False,
            'binary_allowed': False,
            'message_size_bytes': 32,
            'max_message_size_bytes': 1024,
            'observed_messages': 1,
            'rate_limit_threshold': 100,
            'rate_limited': False,
        }]},
    )
    assert ws.status_code == 200, ws.text
    ws_summary = ws.json()['summary']
    assert {key: ws_summary[key] for key in ('total', 'passed', 'failed')} == {
        'total': 1, 'passed': 1, 'failed': 0,
    }
    assert ws_summary['execution_budget']['profile_id'] == budget_id
    assert ws_summary['execution_budget']['allowed'] is True
    ws_fingerprint = ws.json()['observations'][0]['evidence_fingerprint']

    gql = client.post(
        f'/api/v1/web-security/projects/{project.id}/protocols/graphql/evaluate',
        headers=headers,
        json={'budget_id': budget_id, 'target_origin': 'https://app.example', 'cases': [{
            'ref': 'gql-own',
            'identity': identity,
            'resource': resource,
            'endpoint': '/graphql',
            'session_ref': 'session-a',
            'operation_type': 'query',
            'operation_name': 'Record',
            'field_path': 'record.id',
            'expected_allowed': True,
            'server_accepted': True,
            'response_status': 200,
            'errors_count': 0,
            'field_authorized': True,
            'mutation_authorized': True,
            'subscription_owner_ref': '',
            'subscription_tenant_ref': '',
            'sensitive_fields_requested': [],
            'sensitive_fields_returned': [],
            'introspection_requested': False,
            'introspection_expected_allowed': False,
            'batch_size': 1,
            'max_batch_size': 10,
            'depth': 2,
            'max_depth': 8,
            'complexity': 3,
            'max_complexity': 100,
        }]},
    )
    assert gql.status_code == 200, gql.text
    assert gql.json()['summary']['failed'] == 0
    gql_fingerprint = gql.json()['observations'][0]['evidence_fingerprint']

    transition = client.post(
        f'/api/v1/web-security/projects/{project.id}/protocols/cross-protocol/evaluate',
        headers=headers,
        json={'budget_id': budget_id, 'target_origin': 'https://app.example', 'cases': [{
            'ref': 'gql-to-ws',
            'identity': identity,
            'resource': resource,
            'session_ref': 'session-a',
            'from_protocol': 'graphql',
            'to_protocol': 'websocket',
            'operation': 'subscribe',
            'expected_allowed': False,
            'observed_allowed': False,
            'identity_consistent': False,
            'tenant_consistent': False,
            'session_bound': False,
            'source_observation_id': gql.json()['observations'][0]['id'],
            'target_observation_id': ws.json()['observations'][0]['id'],
        }]},
    )
    assert transition.status_code == 200, transition.text
    assert transition.json()['summary']['passed'] == 1
    assert transition.json()['summary']['execution_budget']['profile_id'] == budget_id

    mismatched_credential = create_credential_secret(
        project=project,
        actor=owner,
        name=f'protocol-mismatch-{uuid.uuid4().hex[:8]}',
        kind=CredentialSecret.Kind.TOKEN,
        secret='protocol-mismatch-secret-only',
        scope={
            'protocol_origin': 'https://app.example',
            'protocol_identity_ref': 'bob',
        },
    )
    mismatched_identity = {**identity, 'credential_ref': str(mismatched_credential.id)}
    mismatch = client.post(
        f'/api/v1/web-security/projects/{project.id}/protocols/websocket/evaluate',
        headers=headers,
        json={
            'budget_id': budget_id,
            'target_origin': 'https://app.example',
            'cases': [{
                'ref': 'ws-vault-identity-mismatch',
                'identity': mismatched_identity,
                'resource': resource,
                'channel': 'ws://fixture/ws/tenant-a/record-a',
                'session_ref': 'session-a',
                'origin': 'https://app.example',
                'allowed_origins': ['https://app.example'],
                'authentication_required': True,
                'authenticated': True,
                'session_state': 'active',
                'requested_action': 'subscribe',
                'expected_allowed': True,
                'server_accepted': True,
            }],
        },
    )
    assert mismatch.status_code == 403, mismatch.text
    assert CredentialAccess.objects.filter(
        credential=mismatched_credential,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.DENIED,
    ).exists()

    denied_budget = client.post(
        f'/api/v1/web-security/projects/{project.id}/execution-budgets',
        headers=headers,
        json={
            'name': 'protocol-security-denied',
            'environment': 'staging',
            'allowed_capabilities': ['graphql_security'],
            'max_requests': 10,
            'network_io_bytes': 1048576,
            'browser_sessions': 0,
            'identities': 2,
            'object_mutations': 0,
            'parallelism': 1,
            'cpu_seconds': 30,
            'memory_mb': 128,
            'duration_seconds': 60,
            'state_changes': False,
            'destructive_operations': False,
            'state_change_policy': 'deny',
            'version': 1,
        },
    )
    assert denied_budget.status_code == 201, denied_budget.text
    denied = client.post(
        f'/api/v1/web-security/projects/{project.id}/protocols/websocket/evaluate',
        headers=headers,
        json={
            'budget_id': denied_budget.json()['id'],
            'target_origin': 'https://app.example',
            'cases': [{
                'ref': 'ws-budget-denied',
                'identity': identity,
                'resource': resource,
                'channel': 'ws://fixture/ws/tenant-a/record-a',
                'session_ref': 'session-a',
                'origin': 'https://app.example',
                'allowed_origins': ['https://app.example'],
                'authentication_required': True,
                'authenticated': True,
                'session_state': 'active',
                'requested_action': 'subscribe',
                'expected_allowed': True,
                'server_accepted': True,
            }],
        },
    )
    assert denied.status_code == 403
    assert 'websocket_security' in ' '.join(denied.json()['detail']['failures'])

    graph = client.get(
        f'/api/v1/web-security/projects/{project.id}/graph',
        headers=headers,
    )
    assert graph.status_code == 200
    kinds = {node['kind'] for node in graph.json()['nodes']}
    assert {'websocket_channel', 'graphql_operation', 'session', 'channel'}.issubset(kinds)
    rendered = str({
        'ws': ws.json(),
        'gql': gql.json(),
        'transition': transition.json(),
        'graph': graph.json(),
    })
    assert protocol_secret not in rendered
    assert ws.json()['summary']['credential_bindings'][0]['credential_ref'] == str(credential.id)
    assert ws.json()['summary']['credential_bindings'][0]['protocol_identity_ref'] == 'alice'
