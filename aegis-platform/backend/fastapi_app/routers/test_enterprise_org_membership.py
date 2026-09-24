from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from django_project.users.models import User
from enterprise.models import Organization, OrganizationMembership
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app


@pytest.mark.django_db
def test_organization_owner_can_add_distinct_active_approver_member():
    owner = User.objects.create_user(
        email='org-owner@example.invalid',
        password='Strong-Test-Password-123!',
    )
    approver = User.objects.create_user(
        email='org-approver@example.invalid',
        password='Strong-Test-Password-456!',
    )
    organization = Organization.objects.create(
        name='E2E Membership Test',
        slug='e2e-membership-test',
        owner=owner,
    )
    OrganizationMembership.objects.create(
        organization=organization,
        user=owner,
        role=OrganizationMembership.Role.OWNER,
    )
    current = {'user_id': str(owner.id)}
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: current

    try:
        with TestClient(app) as client:
            response = client.post(
                f'/api/v1/enterprise/organizations/{organization.id}/members',
                json={'email': approver.email, 'role': 'admin'},
            )
        assert response.status_code == 201
        payload = response.json()
        assert payload['organization_id'] == str(organization.id)
        assert payload['user_id'] == str(approver.id)
        assert payload['role'] == OrganizationMembership.Role.ADMIN
        membership = OrganizationMembership.objects.get(pk=payload['id'])
        assert membership.user_id == approver.id
        assert membership.is_active is True
    finally:
        app.dependency_overrides.clear()


@pytest.mark.django_db
def test_non_admin_organization_member_cannot_add_members():
    owner = User.objects.create_user(
        email='org-owner-deny@example.invalid',
        password='Strong-Test-Password-123!',
    )
    viewer = User.objects.create_user(
        email='org-viewer-deny@example.invalid',
        password='Strong-Test-Password-456!',
    )
    target = User.objects.create_user(
        email='org-target-deny@example.invalid',
        password='Strong-Test-Password-789!',
    )
    organization = Organization.objects.create(
        name='E2E Membership Deny',
        slug='e2e-membership-deny',
        owner=owner,
    )
    OrganizationMembership.objects.create(
        organization=organization,
        user=owner,
        role=OrganizationMembership.Role.OWNER,
    )
    OrganizationMembership.objects.create(
        organization=organization,
        user=viewer,
        role=OrganizationMembership.Role.VIEWER,
    )
    current = {'user_id': str(viewer.id)}
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: current

    try:
        with TestClient(app) as client:
            response = client.post(
                f'/api/v1/enterprise/organizations/{organization.id}/members',
                json={'email': target.email, 'role': 'admin'},
            )
        assert response.status_code == 403
        assert not OrganizationMembership.objects.filter(
            organization=organization,
            user=target,
        ).exists()
    finally:
        app.dependency_overrides.clear()
