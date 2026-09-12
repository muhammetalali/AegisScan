from __future__ import annotations

import uuid

import pytest

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
from fastapi_app.main import app
from fastapi_app.routers.web_security import (
    _project_admin_for_user_sync,
    _project_for_user_sync,
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

    assert _project_for_user_sync(str(project.id), str(owner.id)) == project
    assert _project_for_user_sync(str(project.id), str(admin.id)) == project
    assert _project_for_user_sync(str(project.id), str(viewer.id)) == project
    assert _project_for_user_sync(str(project.id), str(outsider.id)) is None

    assert _project_admin_for_user_sync(str(project.id), str(owner.id)) == project
    assert _project_admin_for_user_sync(str(project.id), str(admin.id)) == project
    assert _project_admin_for_user_sync(str(project.id), str(viewer.id)) is None
    assert _project_admin_for_user_sync(str(project.id), str(outsider.id)) is None
