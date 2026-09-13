from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.governed_responsibility_models import (
    GovernedResponsibilityAssignment,
    GovernedResponsibilityEvent,
    GovernedResponsibilityRevocation,
)
from enterprise.models import OrganizationMembership
from fastapi_app.contracts.governed_operations import ActorLayer, EntityRef, ProjectionSnapshot
from fastapi_app.services.governed_operations import list_action_contracts
from fastapi_app.services.governed_responsibility_authority import (
    GovernedResponsibilityConflict,
    GovernedResponsibilityError,
    build_authoritative_manifest,
    grant_responsibility,
    resolve_actor_authority,
    revoke_responsibility,
    verify_responsibility_event_chain,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def responsibility_fixture(disposition_fixture):
    client, owner, project, _asset, _authorization, _scan, _finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    target = User.objects.create_user(
        email='agom-responsibility-target@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='AGOM',
        last_name='Target',
    )
    target_membership = OrganizationMembership.objects.create(
        organization=organization,
        user=target,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    return client, owner, project, organization, owner_membership, target, target_membership


def _grant(*, owner, project, organization, target_membership, key: str, responsibility: str = 'finding_confirmer', **kwargs):
    return grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(owner.id),
        membership_id=str(target_membership.id),
        responsibility=responsibility,
        scope_kind=GovernedResponsibilityAssignment.ScopeKind.PROJECT,
        project_id=str(project.id),
        reason=kwargs.pop('reason', 'Assign governed project duty.'),
        idempotency_key=key,
        **kwargs,
    )


def test_contract_responsibilities_are_backed_by_canonical_assignment_choices():
    canonical = set(GovernedResponsibilityAssignment.Responsibility.values)
    required = {item for contract in list_action_contracts() for item in contract.required_responsibilities}
    assert required <= canonical


def test_owner_grant_is_authoritative_and_hash_chained(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    result = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='grant-owner-1')
    assert result.replayed is False
    authority = resolve_actor_authority(
        organization_id=str(organization.id), user_id=str(target.id), project_id=str(project.id)
    )
    assert authority.role == OrganizationMembership.Role.ANALYST
    assert authority.responsibilities == frozenset({'finding_confirmer'})
    chain = verify_responsibility_event_chain(organization_id=str(organization.id))
    assert chain['valid'] is True
    assert chain['entries'] == 1
    assert len(chain['head']) == 64


def test_non_owner_admin_cannot_govern_assignments(responsibility_fixture):
    _client, _owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    with pytest.raises(PermissionError):
        grant_responsibility(
            organization_id=str(organization.id), actor_id=str(target.id), membership_id=str(target_membership.id),
            responsibility='finding_confirmer', scope_kind='project', project_id=str(project.id),
            reason='Unauthorized self-grant attempt.', idempotency_key='non-admin-grant',
        )


def test_project_and_scope_must_be_tenant_valid(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    other = Project.objects.create(name='Outside responsibility project', slug='outside-responsibility-project', owner=owner)
    with pytest.raises(GovernedResponsibilityError, match='outside the organization scope'):
        grant_responsibility(
            organization_id=str(organization.id), actor_id=str(owner.id), membership_id=str(target_membership.id),
            responsibility='finding_confirmer', scope_kind='project', project_id=str(other.id),
            reason='Invalid tenant scope.', idempotency_key='outside-project',
        )
    with pytest.raises(GovernedResponsibilityError, match='Organization-scoped'):
        grant_responsibility(
            organization_id=str(organization.id), actor_id=str(owner.id), membership_id=str(target_membership.id),
            responsibility='finding_confirmer', scope_kind='organization', project_id=str(project.id),
            reason='Invalid shape.', idempotency_key='bad-scope-shape',
        )


def test_exact_grant_idempotency_replays_even_with_automatic_valid_from(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    first = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='grant-replay')
    second = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='grant-replay')
    assert first.replayed is False
    assert second.replayed is True
    assert first.assignment.id == second.assignment.id
    assert GovernedResponsibilityAssignment.objects.count() == 1
    assert GovernedResponsibilityEvent.objects.count() == 1


def test_grant_idempotency_key_conflict_is_rejected(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='grant-conflict')
    with pytest.raises(GovernedResponsibilityConflict, match='Idempotency key'):
        _grant(
            owner=owner, project=project, organization=organization, target_membership=target_membership,
            key='grant-conflict', reason='Different governed intent.',
        )


def test_overlapping_current_exact_scope_requires_explicit_supersession(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='overlap-1')
    with pytest.raises(GovernedResponsibilityConflict, match='overlapping current assignment'):
        _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='overlap-2')


def test_supersession_replaces_authority_without_mutating_old_grant(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    old = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='supersede-old')
    new = _grant(
        owner=owner, project=project, organization=organization, target_membership=target_membership,
        key='supersede-new', supersedes_assignment_id=str(old.assignment.id), reason='Rotate governed duty evidence.',
    )
    old.assignment.refresh_from_db()
    assert old.assignment.superseded_by.id == new.assignment.id
    assert old.assignment.is_currently_valid is False
    authority = resolve_actor_authority(
        organization_id=str(organization.id), user_id=str(target.id), project_id=str(project.id)
    )
    assert authority.responsibilities == frozenset({'finding_confirmer'})
    assert list(GovernedResponsibilityEvent.objects.values_list('event_type', flat=True)) == ['granted', 'superseded', 'granted']
    assert verify_responsibility_event_chain(organization_id=str(organization.id))['valid'] is True


def test_expired_assignment_is_not_authority(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    now = timezone.now()
    result = _grant(
        owner=owner, project=project, organization=organization, target_membership=target_membership,
        key='expired-grant', valid_from=now - timedelta(hours=2), valid_until=now - timedelta(hours=1),
    )
    assert result.assignment.is_currently_valid is False
    authority = resolve_actor_authority(
        organization_id=str(organization.id), user_id=str(target.id), project_id=str(project.id)
    )
    assert authority.responsibilities == frozenset()


def test_revocation_removes_authority_and_exact_retry_replays(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    grant = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='revoke-source')
    first = revoke_responsibility(
        assignment_id=str(grant.assignment.id), actor_id=str(owner.id), reason='Duty no longer required.', idempotency_key='revoke-1'
    )
    second = revoke_responsibility(
        assignment_id=str(grant.assignment.id), actor_id=str(owner.id), reason='Duty no longer required.', idempotency_key='revoke-1'
    )
    assert first.replayed is False
    assert second.replayed is True
    assert first.revocation.id == second.revocation.id
    authority = resolve_actor_authority(
        organization_id=str(organization.id), user_id=str(target.id), project_id=str(project.id)
    )
    assert authority.responsibilities == frozenset()
    assert verify_responsibility_event_chain(organization_id=str(organization.id))['valid'] is True


def test_revoke_rejects_new_key_after_commit_and_conflicting_key_reuse(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    grant = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='revoke-conflict-source')
    revoke_responsibility(
        assignment_id=str(grant.assignment.id), actor_id=str(owner.id), reason='Revoke governed duty.', idempotency_key='revoke-original'
    )
    with pytest.raises(GovernedResponsibilityConflict, match='original idempotency key'):
        revoke_responsibility(
            assignment_id=str(grant.assignment.id), actor_id=str(owner.id), reason='Revoke governed duty.', idempotency_key='revoke-new-key'
        )
    other = _grant(
        owner=owner, project=project, organization=organization, target_membership=target_membership,
        key='other-source', responsibility='campaign_assessor',
    )
    with pytest.raises(GovernedResponsibilityConflict, match='Idempotency key'):
        revoke_responsibility(
            assignment_id=str(other.assignment.id), actor_id=str(owner.id), reason='Different revoke.', idempotency_key='revoke-original'
        )


def test_assignment_revocation_and_events_reject_instance_and_queryset_mutation(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    grant = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='immutable-source')
    grant.assignment.reason = 'tampered'
    with pytest.raises(ValidationError):
        grant.assignment.save()
    with pytest.raises(ValidationError):
        GovernedResponsibilityAssignment.objects.filter(pk=grant.assignment.id).update(reason='tampered')
    with pytest.raises(ValidationError):
        GovernedResponsibilityAssignment.objects.filter(pk=grant.assignment.id).delete()
    event = GovernedResponsibilityEvent.objects.get()
    with pytest.raises(ValidationError):
        GovernedResponsibilityEvent.objects.filter(pk=event.id).update(payload={'tampered': True})
    revocation = revoke_responsibility(
        assignment_id=str(grant.assignment.id), actor_id=str(owner.id), reason='Immutable revoke.', idempotency_key='immutable-revoke'
    ).revocation
    with pytest.raises(ValidationError):
        GovernedResponsibilityRevocation.objects.filter(pk=revocation.id).delete()


def test_inactive_membership_cannot_resolve_authority(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='inactive-member-source')
    target_membership.is_active = False
    target_membership.save(update_fields=['is_active'])
    with pytest.raises(PermissionError, match='Active organization membership'):
        resolve_actor_authority(
            organization_id=str(organization.id), user_id=str(target.id), project_id=str(project.id)
        )


def test_authoritative_manifest_uses_database_role_and_responsibility(responsibility_fixture):
    _client, owner, project, organization, _owner_membership, target, target_membership = responsibility_fixture
    _grant(
        owner=owner, project=project, organization=organization, target_membership=target_membership,
        key='manifest-duty', responsibility='finding_confirmer',
    )
    manifest = build_authoritative_manifest(
        organization_id=str(organization.id), user_id=str(target.id), actor_layer=ActorLayer.ASSURE,
        entity=EntityRef(entity_type='finding', entity_id='finding-1', project_id=str(project.id)),
        projection=ProjectionSnapshot(lifecycle='pending_confirmation'),
        evidence_ready_actions={'finding.confirm'}, sod_eligible_actions={'finding.confirm'}, gate_results_by_action={},
    )
    confirm = next(item for item in manifest.capabilities if item.action_id == 'finding.confirm')
    assert manifest.actor_role == OrganizationMembership.Role.ANALYST
    assert manifest.actor_responsibilities == ['finding_confirmer']
    assert confirm.reason_code == 'GATE_NOT_SATISFIED'


def test_postgresql_concurrent_exact_grant_is_single_result(responsibility_fixture):
    assert connection.vendor == 'postgresql'
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return _grant(
                owner=owner, project=project, organization=organization, target_membership=target_membership,
                key='concurrent-same-grant',
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(item.replayed for item in results) == [False, True]
    assert len({item.assignment.id for item in results}) == 1
    assert GovernedResponsibilityAssignment.objects.count() == 1
    assert GovernedResponsibilityEvent.objects.count() == 1
    assert verify_responsibility_event_chain(organization_id=str(organization.id))['valid'] is True


def test_postgresql_concurrent_supersession_allows_one_winner(responsibility_fixture):
    assert connection.vendor == 'postgresql'
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    original = _grant(owner=owner, project=project, organization=organization, target_membership=target_membership, key='race-old')
    barrier = Barrier(2)

    def worker(key: str):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                return _grant(
                    owner=owner, project=project, organization=organization, target_membership=target_membership,
                    key=key, supersedes_assignment_id=str(original.assignment.id), reason='Concurrent supersession.',
                )
            except GovernedResponsibilityConflict as exc:
                return exc
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, ['race-new-a', 'race-new-b']))
    winners = [item for item in results if not isinstance(item, Exception)]
    conflicts = [item for item in results if isinstance(item, GovernedResponsibilityConflict)]
    assert len(winners) == 1
    assert len(conflicts) == 1
    assert GovernedResponsibilityAssignment.objects.count() == 2
    assert verify_responsibility_event_chain(organization_id=str(organization.id))['valid'] is True


def test_postgresql_same_org_concurrent_events_keep_single_hash_chain(responsibility_fixture):
    assert connection.vendor == 'postgresql'
    _client, owner, project, organization, _owner_membership, _target, target_membership = responsibility_fixture
    barrier = Barrier(2)

    def worker(args):
        responsibility, key = args
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return _grant(
                owner=owner, project=project, organization=organization, target_membership=target_membership,
                key=key, responsibility=responsibility,
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(worker, [('finding_confirmer', 'chain-a'), ('campaign_assessor', 'chain-b')]))
    assert GovernedResponsibilityEvent.objects.count() == 2
    chain = verify_responsibility_event_chain(organization_id=str(organization.id))
    assert chain['valid'] is True
    assert chain['entries'] == 2
