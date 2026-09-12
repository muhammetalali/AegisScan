from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from django_project.projects.models import Project, ProjectMembership
from django_project.users.models import User
from fastapi_app.contracts.web_security_v2 import (
    AuthorizationMatrixIn,
    AuthorizationPolicyIn,
    ExecutionBudgetIn,
    GraphSnapshotIn,
    NegativePathBatchIn,
    ProviderApprovalIn,
    ResponseComparisonIn,
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
