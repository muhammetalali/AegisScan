from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.db import close_old_connections, connection

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.governed_responsibility_models import (
    GovernedResponsibilityAssignment,
    GovernedResponsibilityRevocation,
)
from enterprise.models import Organization, OrganizationMembership, TenantProject
from fastapi_app.services.governed_responsibility_authority import (
    GovernedResponsibilityConflict,
    grant_responsibility,
    revoke_responsibility,
    verify_responsibility_event_chain,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def test_postgresql_revoke_vs_supersede_has_one_winner_no_deadlock(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, owner, project, _asset, _authorization, _scan, _finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    target = User.objects.create_user(
        email='agom-lock-order-target@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='AGOM',
        last_name='Lock Order',
    )
    target_membership = OrganizationMembership.objects.create(
        organization=organization,
        user=target,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    original = grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(owner.id),
        membership_id=str(target_membership.id),
        responsibility='finding_confirmer',
        scope_kind='project',
        project_id=str(project.id),
        reason='Seed duty for revoke/supersede lock-order race.',
        idempotency_key='lock-order-seed',
    ).assignment
    barrier = Barrier(2)

    def revoke_worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                return revoke_responsibility(
                    assignment_id=str(original.id),
                    actor_id=str(owner.id),
                    reason='Concurrent revoke.',
                    idempotency_key='lock-order-revoke',
                )
            except GovernedResponsibilityConflict as exc:
                return exc
        finally:
            close_old_connections()

    def supersede_worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                return grant_responsibility(
                    organization_id=str(organization.id),
                    actor_id=str(owner.id),
                    membership_id=str(target_membership.id),
                    responsibility='finding_confirmer',
                    scope_kind='project',
                    project_id=str(project.id),
                    reason='Concurrent supersession.',
                    idempotency_key='lock-order-supersede',
                    supersedes_assignment_id=str(original.id),
                )
            except GovernedResponsibilityConflict as exc:
                return exc
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(revoke_worker), pool.submit(supersede_worker)]
        results = [future.result(timeout=20) for future in futures]

    conflicts = [item for item in results if isinstance(item, GovernedResponsibilityConflict)]
    successes = [item for item in results if not isinstance(item, Exception)]
    assert len(successes) == 1
    assert len(conflicts) == 1

    original.refresh_from_db()
    revoked = GovernedResponsibilityRevocation.objects.filter(assignment=original).exists()
    superseded = GovernedResponsibilityAssignment.objects.filter(supersedes=original).exists()
    assert revoked ^ superseded
    assert verify_responsibility_event_chain(organization_id=str(organization.id))['valid'] is True


def test_same_idempotency_keys_are_isolated_between_organizations(disposition_fixture):
    _client, owner, project_a, _asset, _authorization, _scan, _finding, organization_a, owner_membership_a = disposition_fixture
    owner_membership_a.role = OrganizationMembership.Role.OWNER
    owner_membership_a.save(update_fields=['role'])

    target_a = User.objects.create_user(
        email='agom-tenant-a-target@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Tenant',
        last_name='A',
    )
    membership_a = OrganizationMembership.objects.create(
        organization=organization_a,
        user=target_a,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )

    project_b = Project.objects.create(name='AGOM Tenant B', slug='agom-tenant-b', owner=owner)
    organization_b = Organization.objects.create(name='AGOM Tenant B', slug='agom-tenant-b', owner=owner)
    TenantProject.objects.create(organization=organization_b, project=project_b)
    OrganizationMembership.objects.create(
        organization=organization_b,
        user=owner,
        role=OrganizationMembership.Role.OWNER,
        is_active=True,
    )
    target_b = User.objects.create_user(
        email='agom-tenant-b-target@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Tenant',
        last_name='B',
    )
    membership_b = OrganizationMembership.objects.create(
        organization=organization_b,
        user=target_b,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )

    grant_a = grant_responsibility(
        organization_id=str(organization_a.id),
        actor_id=str(owner.id),
        membership_id=str(membership_a.id),
        responsibility='finding_confirmer',
        scope_kind='project',
        project_id=str(project_a.id),
        reason='Tenant A same-key grant.',
        idempotency_key='same-cross-tenant-key',
    )
    grant_b = grant_responsibility(
        organization_id=str(organization_b.id),
        actor_id=str(owner.id),
        membership_id=str(membership_b.id),
        responsibility='finding_confirmer',
        scope_kind='project',
        project_id=str(project_b.id),
        reason='Tenant B same-key grant.',
        idempotency_key='same-cross-tenant-key',
    )
    assert grant_a.assignment.id != grant_b.assignment.id
    assert grant_a.replayed is False
    assert grant_b.replayed is False

    revoke_a = revoke_responsibility(
        assignment_id=str(grant_a.assignment.id),
        actor_id=str(owner.id),
        reason='Tenant A same-key revoke.',
        idempotency_key='same-cross-tenant-revoke',
    )
    revoke_b = revoke_responsibility(
        assignment_id=str(grant_b.assignment.id),
        actor_id=str(owner.id),
        reason='Tenant B same-key revoke.',
        idempotency_key='same-cross-tenant-revoke',
    )
    assert revoke_a.revocation.id != revoke_b.revocation.id
    assert verify_responsibility_event_chain(organization_id=str(organization_a.id))['valid'] is True
    assert verify_responsibility_event_chain(organization_id=str(organization_b.id))['valid'] is True
