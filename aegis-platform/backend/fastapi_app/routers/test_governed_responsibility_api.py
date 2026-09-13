from __future__ import annotations

import pytest

from django_project.users.models import User
from enterprise.models import OrganizationMembership
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def authority_api_fixture(disposition_fixture):
    client, owner, project, _asset, _authorization, _scan, _finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    target = User.objects.create_user(
        email='agom-api-target@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='AGOM',
        last_name='API Target',
    )
    target_membership = OrganizationMembership.objects.create(
        organization=organization,
        user=target,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    return client, owner, project, organization, target, target_membership


def _grant_body(*, project, organization, target_membership, key='api-grant-1'):
    return {
        'organization_id': str(organization.id),
        'membership_id': str(target_membership.id),
        'responsibility': 'finding_confirmer',
        'scope_kind': 'project',
        'project_id': str(project.id),
        'reason': 'API-governed assignment for confirmation duty.',
        'idempotency_key': key,
    }


def test_grant_endpoint_is_idempotent_and_chain_is_verifiable(authority_api_fixture):
    client, _owner, project, organization, _target, target_membership = authority_api_fixture
    body = _grant_body(project=project, organization=organization, target_membership=target_membership)
    first = client.post('/api/v1/assurance/governance/responsibilities/grants', json=body)
    second = client.post('/api/v1/assurance/governance/responsibilities/grants', json=body)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()['assignment_id'] == second.json()['assignment_id']
    assert first.json()['replayed'] is False
    assert second.json()['replayed'] is True

    chain = client.get(
        '/api/v1/assurance/governance/responsibilities/chain',
        params={'organization_id': str(organization.id)},
    )
    assert chain.status_code == 200, chain.text
    assert chain.json()['valid'] is True
    assert chain.json()['entries'] == 1


def test_authority_endpoint_derives_actor_from_authenticated_session(authority_api_fixture):
    client, _owner, project, organization, target, target_membership = authority_api_fixture
    body = _grant_body(project=project, organization=organization, target_membership=target_membership, key='api-authority-grant')
    response = client.post('/api/v1/assurance/governance/responsibilities/grants', json=body)
    assert response.status_code == 200, response.text

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(target.id),
        'is_staff': False,
    }
    authority = client.get(
        '/api/v1/assurance/governance/responsibilities/authority',
        params={'organization_id': str(organization.id), 'project_id': str(project.id)},
    )
    assert authority.status_code == 200, authority.text
    payload = authority.json()
    assert payload['membership_id'] == str(target_membership.id)
    assert payload['role'] == 'analyst'
    assert payload['responsibilities'] == ['finding_confirmer']


def test_client_cannot_assert_role_or_responsibility_authority(authority_api_fixture):
    client, _owner, project, organization, _target, target_membership = authority_api_fixture
    body = _grant_body(project=project, organization=organization, target_membership=target_membership, key='api-forbid-authority')
    body['actor_role'] = 'owner'
    body['actor_responsibilities'] = ['campaign_lead']
    response = client.post('/api/v1/assurance/governance/responsibilities/grants', json=body)
    assert response.status_code == 422


def test_non_owner_admin_session_cannot_grant(authority_api_fixture):
    client, _owner, project, organization, target, target_membership = authority_api_fixture
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(target.id),
        'is_staff': False,
    }
    response = client.post(
        '/api/v1/assurance/governance/responsibilities/grants',
        json=_grant_body(project=project, organization=organization, target_membership=target_membership, key='api-forbidden-grant'),
    )
    assert response.status_code == 403


def test_revoke_endpoint_removes_current_authority(authority_api_fixture):
    client, _owner, project, organization, target, target_membership = authority_api_fixture
    grant = client.post(
        '/api/v1/assurance/governance/responsibilities/grants',
        json=_grant_body(project=project, organization=organization, target_membership=target_membership, key='api-revoke-source'),
    )
    assert grant.status_code == 200, grant.text
    assignment_id = grant.json()['assignment_id']
    first = client.post(
        f'/api/v1/assurance/governance/responsibilities/{assignment_id}/revoke',
        json={'reason': 'Remove confirmation duty.', 'idempotency_key': 'api-revoke-1'},
    )
    second = client.post(
        f'/api/v1/assurance/governance/responsibilities/{assignment_id}/revoke',
        json={'reason': 'Remove confirmation duty.', 'idempotency_key': 'api-revoke-1'},
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()['revocation_id'] == second.json()['revocation_id']
    assert second.json()['replayed'] is True

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(target.id),
        'is_staff': False,
    }
    authority = client.get(
        '/api/v1/assurance/governance/responsibilities/authority',
        params={'organization_id': str(organization.id), 'project_id': str(project.id)},
    )
    assert authority.status_code == 200, authority.text
    assert authority.json()['responsibilities'] == []
