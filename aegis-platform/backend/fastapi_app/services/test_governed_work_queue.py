from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.projects.models import ProjectMembership
from django_project.users.models import User
from enterprise.assurance_obligation_models import AssuranceObligation
from enterprise.models import DecisionAction, InvestigationCase, OrganizationMembership
from enterprise.soc_models import InvestigationCaseState
from enterprise.work_queue_models import GovernedWorkClaim, GovernedWorkClaimEvent
from fastapi_app.services.assurance_obligation_governance import materialize_assurance_obligation
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.governed_work_queue import (
    GovernedWorkQueueConflict,
    StaleGovernedWorkClaimVersion,
    list_governed_work,
    mutate_governed_work_claim,
)
from fastapi_app.services.test_assurance_obligation_governance import _disposition, _schedule
from fastapi_app.services.test_finding_disposition import disposition_fixture
from fastapi_app.services.test_soc_closure_governance import _case


pytestmark = pytest.mark.django_db(transaction=True)


def _pending_request(user, project, finding, marker='queue'):
    return create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(user.id),
        action_id='finding.disposition.accept_risk',
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key=f'a5-request-{marker}-0001',
        parameters={'rationale': f'A5 governed queue proposal {marker}.'},
    ).request


def _decision_action(user, project, organization, marker='queue'):
    now = timezone.now()
    return DecisionAction.objects.create(
        action_id=f'a5-action-{marker}-{uuid4().hex[:8]}',
        organization=organization,
        project=project,
        decision_id=f'a5-decision-{marker}',
        node_id=f'a5-node-{marker}',
        title=f'A5 remediation {marker}',
        owner=str(user.id),
        requested_by=str(user.id),
        sla_hours=4,
        state='pending',
        risk_before=85,
        confidence_before=90,
        priority=88,
        recommended_action='Remediate and validate.',
        remediation_plan=[],
        created_at=now,
        updated_at=now,
    )


def test_queue_projects_authoritative_sources_without_copying_business_state(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    request = _pending_request(user, project, finding)
    action = _decision_action(user, project, organization)
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='a5-obligation')
    obligation = materialize_assurance_obligation(
        project_id=str(project.id),
        finding_id=str(finding.id),
        user_id=str(user.id),
        schedule_id=str(schedule.id),
    ).obligation
    case, state = _case(user, project, organization, finding)

    payload = list_governed_work(actor_id=str(user.id), project_id=str(project.id))
    by_key = {item['item_key']: item for item in payload['items']}

    request_item = by_key[f'governed_action_request:{request.id}']
    action_item = by_key[f'decision_action:{action.action_id}']
    obligation_item = by_key[f'assurance_obligation:{obligation.id}']
    case_item = by_key[f'investigation_case:{case.id}']

    assert payload['policy_version'] == 'agom.work-queue.v1'
    assert request_item['authoritative_state'] == 'pending_approval'
    assert request_item['source_version'] == request.expected_version
    assert action_item['authoritative_state'] == action.state
    assert action_item['source_version'] == action.version
    assert obligation_item['authoritative_state'] == obligation.status
    assert obligation_item['source_version'] == obligation.version
    assert case_item['authoritative_state'] == case.status
    assert case_item['source_version'] == state.version
    assert all(item['claim']['version'] == 0 for item in [request_item, action_item, obligation_item, case_item])


def test_claim_renew_release_are_versioned_idempotent_and_append_only(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    request = _pending_request(user, project, finding, marker='lifecycle')

    first = mutate_governed_work_claim(
        actor_id=str(user.id),
        project_id=str(project.id),
        source_type='governed_action_request',
        source_id=str(request.id),
        operation='claim',
        expected_version=0,
        idempotency_key='a5-claim-lifecycle-0001',
        lease_seconds=300,
    )
    replay = mutate_governed_work_claim(
        actor_id=str(user.id),
        project_id=str(project.id),
        source_type='governed_action_request',
        source_id=str(request.id),
        operation='claim',
        expected_version=0,
        idempotency_key='a5-claim-lifecycle-0001',
        lease_seconds=300,
    )
    assert first.replayed is False
    assert replay.replayed is True
    assert replay.snapshot == first.snapshot
    assert first.snapshot['claim']['version'] == 1
    assert first.snapshot['claim']['state'] == 'claimed'

    renewed = mutate_governed_work_claim(
        actor_id=str(user.id),
        project_id=str(project.id),
        source_type='governed_action_request',
        source_id=str(request.id),
        operation='renew',
        expected_version=1,
        idempotency_key='a5-renew-lifecycle-0001',
        lease_seconds=600,
    )
    assert renewed.snapshot['claim']['version'] == 2
    assert renewed.snapshot['claim']['mine'] is True

    released = mutate_governed_work_claim(
        actor_id=str(user.id),
        project_id=str(project.id),
        source_type='governed_action_request',
        source_id=str(request.id),
        operation='release',
        expected_version=2,
        idempotency_key='a5-release-lifecycle-0001',
    )
    assert released.snapshot['claim']['version'] == 3
    assert released.snapshot['claim']['state'] == 'unclaimed'

    claim = GovernedWorkClaim.objects.get(source_id=str(request.id))
    events = list(GovernedWorkClaimEvent.objects.filter(claim=claim).order_by('sequence'))
    assert [event.event_type for event in events] == ['claimed', 'renewed', 'released']
    assert [event.sequence for event in events] == [1, 2, 3]
    assert events[0].previous_hash == ''
    assert events[1].previous_hash == events[0].entry_hash
    assert events[2].previous_hash == events[1].entry_hash
    event = events[0]
    event.result_snapshot = {'tampered': True}
    with pytest.raises(ValidationError):
        event.save()
    with pytest.raises(ValidationError):
        GovernedWorkClaimEvent.objects.filter(pk=event.pk).update(result_snapshot={})


def test_claim_rejects_stale_version_and_active_foreign_owner(disposition_fixture):
    _client, owner, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    request = _pending_request(owner, project, finding, marker='conflict')
    other = User.objects.create_user(email='a5-other@example.invalid', password='Strong-Test-Password-123!')
    project.members.add(other)
    OrganizationMembership.objects.create(
        organization=organization,
        user=other,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )

    mutate_governed_work_claim(
        actor_id=str(owner.id), project_id=str(project.id),
        source_type='governed_action_request', source_id=str(request.id),
        operation='claim', expected_version=0,
        idempotency_key='a5-owner-claim-0001', lease_seconds=300,
    )
    with pytest.raises(StaleGovernedWorkClaimVersion):
        mutate_governed_work_claim(
            actor_id=str(other.id), project_id=str(project.id),
            source_type='governed_action_request', source_id=str(request.id),
            operation='claim', expected_version=0,
            idempotency_key='a5-other-stale-0001', lease_seconds=300,
        )
    with pytest.raises(GovernedWorkQueueConflict, match='another actor'):
        mutate_governed_work_claim(
            actor_id=str(other.id), project_id=str(project.id),
            source_type='governed_action_request', source_id=str(request.id),
            operation='claim', expected_version=1,
            idempotency_key='a5-other-active-0001', lease_seconds=300,
        )


def test_idempotent_replay_is_blocked_after_membership_revocation(disposition_fixture):
    _client, owner, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    request = _pending_request(owner, project, finding, marker='revoked')
    member = User.objects.create_user(email='a5-revoked@example.invalid', password='Strong-Test-Password-123!')
    ProjectMembership.objects.create(project=project, user=member, role=ProjectMembership.Role.MEMBER)
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=member,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    first = mutate_governed_work_claim(
        actor_id=str(member.id), project_id=str(project.id),
        source_type='governed_action_request', source_id=str(request.id),
        operation='claim', expected_version=0,
        idempotency_key='a5-revoked-replay-0001', lease_seconds=300,
    )
    assert first.replayed is False
    membership.is_active = False
    membership.save(update_fields=['is_active', 'updated_at'])

    with pytest.raises(PermissionError):
        mutate_governed_work_claim(
            actor_id=str(member.id), project_id=str(project.id),
            source_type='governed_action_request', source_id=str(request.id),
            operation='claim', expected_version=0,
            idempotency_key='a5-revoked-replay-0001', lease_seconds=300,
        )


def test_viewer_can_read_but_cannot_claim(disposition_fixture):
    _client, owner, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    request = _pending_request(owner, project, finding, marker='viewer')
    viewer = User.objects.create_user(email='a5-viewer@example.invalid', password='Strong-Test-Password-123!')
    ProjectMembership.objects.create(project=project, user=viewer, role=ProjectMembership.Role.MEMBER)
    OrganizationMembership.objects.create(
        organization=organization,
        user=viewer,
        role=OrganizationMembership.Role.VIEWER,
        is_active=True,
    )
    payload = list_governed_work(actor_id=str(viewer.id), project_id=str(project.id))
    assert any(item['source_id'] == str(request.id) for item in payload['items'])
    with pytest.raises(PermissionError):
        mutate_governed_work_claim(
            actor_id=str(viewer.id), project_id=str(project.id),
            source_type='governed_action_request', source_id=str(request.id),
            operation='claim', expected_version=0,
            idempotency_key='a5-viewer-claim-0001', lease_seconds=300,
        )


def test_completed_source_disappears_without_mutating_claim_history(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, _finding, organization, _membership = disposition_fixture
    action = _decision_action(user, project, organization, marker='terminal')
    claimed = mutate_governed_work_claim(
        actor_id=str(user.id), project_id=str(project.id),
        source_type='decision_action', source_id=action.action_id,
        operation='claim', expected_version=0,
        idempotency_key='a5-terminal-claim-0001', lease_seconds=300,
    )
    assert claimed.snapshot['claim']['state'] == 'claimed'

    action.state = 'verified'
    action.version += 1
    action.updated_at = timezone.now()
    action.save(update_fields=['state', 'version', 'updated_at'])

    payload = list_governed_work(actor_id=str(user.id), project_id=str(project.id))
    assert not any(item['source_id'] == action.action_id for item in payload['items'])
    assert GovernedWorkClaim.objects.filter(source_id=action.action_id).count() == 1
    assert GovernedWorkClaimEvent.objects.filter(claim__source_id=action.action_id).count() == 1


def test_postgresql_concurrent_first_claim_serializes_to_one_winner(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, owner, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    request = _pending_request(owner, project, finding, marker='concurrent')
    other = User.objects.create_user(email='a5-concurrent@example.invalid', password='Strong-Test-Password-123!')
    project.members.add(other)
    OrganizationMembership.objects.create(
        organization=organization,
        user=other,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    barrier = Barrier(2)

    def worker(actor, key):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                result = mutate_governed_work_claim(
                    actor_id=str(actor.id), project_id=str(project.id),
                    source_type='governed_action_request', source_id=str(request.id),
                    operation='claim', expected_version=0,
                    idempotency_key=key, lease_seconds=300,
                )
                return ('ok', result.snapshot['claim']['claimed_by_id'])
            except (StaleGovernedWorkClaimVersion, GovernedWorkQueueConflict) as exc:
                return ('conflict', type(exc).__name__)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda pair: worker(*pair), [
            (owner, 'a5-concurrent-owner-0001'),
            (other, 'a5-concurrent-other-0001'),
        ]))

    assert sorted(result[0] for result in results) == ['conflict', 'ok']
    claim = GovernedWorkClaim.objects.get(source_id=str(request.id))
    assert str(claim.claimed_by_id) in {str(owner.id), str(other.id)}
    assert GovernedWorkClaimEvent.objects.filter(claim=claim).count() == 1
