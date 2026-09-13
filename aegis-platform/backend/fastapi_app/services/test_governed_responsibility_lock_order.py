from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.db import close_old_connections, connection

from django_project.users.models import User
from enterprise.governed_responsibility_models import (
    GovernedResponsibilityAssignment,
    GovernedResponsibilityRevocation,
)
from enterprise.models import OrganizationMembership
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
