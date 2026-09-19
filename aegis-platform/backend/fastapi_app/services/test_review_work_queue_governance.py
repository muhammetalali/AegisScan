from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.assurance_obligation_models import AssuranceObligation, AssuranceObligationEvent
from enterprise.models import Organization, OrganizationMembership, TenantProject
from fastapi_app.routers.assurance_obligations import (
    AssuranceObligationAcknowledgeRequest,
    AssuranceObligationAssignmentRequest,
)
from fastapi_app.services.assurance_obligation_governance import (
    AssuranceObligationError,
    acknowledge_assurance_obligation,
    assign_assurance_obligation,
    list_review_work_queue,
    materialize_assurance_obligation,
    refresh_assurance_obligation,
)
from fastapi_app.services.test_assurance_obligation_governance import _disposition, _schedule
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def _materialized(disposition_fixture, *, marker='work-queue', days=30, now=None):
    _client, user, project, asset, authorization, _scan, finding, organization, membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    disposition = _disposition(user, project, finding, marker=marker, days=days)
    result = materialize_assurance_obligation(
        project_id=str(project.id),
        finding_id=str(finding.id),
        user_id=str(user.id),
        schedule_id=str(schedule.id),
        now=now,
    )
    result.obligation.refresh_from_db()
    return user, project, finding, organization, membership, disposition, result.obligation


def _reviewer(*, owner, project, organization, email: str, role=OrganizationMembership.Role.ANALYST):
    user = User.objects.create_user(
        email=email,
        password='Strong-Test-Password-123!',
        first_name='Queue',
        last_name='Reviewer',
    )
    project.members.add(user)
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=role,
        is_active=True,
    )
    return user, membership


def test_materialization_is_authoritative_work_queue_source(disposition_fixture):
    user, project, finding, _organization, membership, _disposition_row, obligation = _materialized(disposition_fixture)

    assert obligation.assigned_to_id == membership.id
    assert obligation.assigned_by_id == user.id
    assert obligation.assigned_at is not None
    assert obligation.policy_id
    assert obligation.policy_version >= 1
    assert obligation.priority in AssuranceObligation.Priority.values
    assert obligation.sla_status == AssuranceObligation.SLAStatus.ON_TRACK
    assert AssuranceObligationEvent.objects.filter(
        obligation=obligation,
        event_type=AssuranceObligationEvent.EventType.ASSIGNED,
    ).count() == 1

    items = list_review_work_queue(project_id=str(project.id), user_id=str(user.id))
    assert len(items) == 1
    assert items[0]['id'] == str(obligation.id)
    assert items[0]['queue_item_id'] == f'assurance-obligation:{obligation.id}'
    assert items[0]['finding_id'] == str(finding.id)
    assert items[0]['assigned_to']['membership_id'] == str(membership.id)
    assert items[0]['assigned_to_me'] is True


def test_due_and_overdue_drive_durable_sla_escalation(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    disposition = _disposition(user, project, finding, marker='sla-escalation', days=30)

    due_now = disposition.review_at - timedelta(hours=12)
    obligation = materialize_assurance_obligation(
        project_id=str(project.id),
        finding_id=str(finding.id),
        user_id=str(user.id),
        schedule_id=str(schedule.id),
        now=due_now,
    ).obligation
    obligation.refresh_from_db()

    assert obligation.status == AssuranceObligation.Status.DUE
    assert obligation.sla_status == AssuranceObligation.SLAStatus.AT_RISK
    assert obligation.escalation_level == 1
    assert obligation.last_escalated_at == due_now
    assert AssuranceObligationEvent.objects.filter(
        obligation=obligation,
        event_type=AssuranceObligationEvent.EventType.SLA_AT_RISK,
    ).count() == 1

    breached_now = disposition.review_at + timedelta(minutes=1)
    refreshed = refresh_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(user.id),
        now=breached_now,
    )
    refreshed.refresh_from_db()

    assert refreshed.status == AssuranceObligation.Status.OVERDUE
    assert refreshed.sla_status == AssuranceObligation.SLAStatus.BREACHED
    assert refreshed.escalation_level == 2
    assert refreshed.last_escalated_at == breached_now
    assert AssuranceObligationEvent.objects.filter(
        obligation=refreshed,
        event_type=AssuranceObligationEvent.EventType.SLA_BREACHED,
    ).count() == 1

    refresh_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(user.id),
        now=breached_now + timedelta(minutes=1),
    )
    assert AssuranceObligationEvent.objects.filter(
        obligation=refreshed,
        event_type=AssuranceObligationEvent.EventType.SLA_BREACHED,
    ).count() == 1


def test_assignment_is_tenant_project_scoped_and_cas_guarded(disposition_fixture):
    owner, project, _finding, organization, _owner_membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='assignment',
    )
    reviewer, reviewer_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='queue-reviewer@example.invalid',
    )
    before = obligation.version

    assigned = assign_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(owner.id),
        assignee_membership_id=str(reviewer_membership.id),
        expected_version=before,
    )
    assigned.refresh_from_db()

    assert assigned.assigned_to_id == reviewer_membership.id
    assert assigned.assigned_to.user_id == reviewer.id
    assert assigned.version == before + 1
    assert AssuranceObligationEvent.objects.filter(
        obligation=assigned,
        event_type=AssuranceObligationEvent.EventType.ASSIGNED,
    ).count() == 2

    with pytest.raises(AssuranceObligationError, match='Expected obligation version'):
        assign_assurance_obligation(
            project_id=str(project.id),
            obligation_id=str(obligation.id),
            user_id=str(owner.id),
            assignee_membership_id=str(obligation.assigned_to_id),
            expected_version=before,
        )


def test_cross_tenant_and_non_project_assignee_are_rejected(disposition_fixture):
    owner, project, _finding, organization, _membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='scope-reject',
    )

    outsider = User.objects.create_user(
        email='other-tenant-reviewer@example.invalid',
        password='Strong-Test-Password-123!',
    )
    other_org = Organization.objects.create(
        name='Other queue tenant',
        slug='other-queue-tenant',
        owner=outsider,
        is_active=True,
    )
    other_membership = OrganizationMembership.objects.create(
        organization=other_org,
        user=outsider,
        role=OrganizationMembership.Role.MANAGER,
        is_active=True,
    )
    with pytest.raises(AssuranceObligationError, match='active reviewer'):
        assign_assurance_obligation(
            project_id=str(project.id),
            obligation_id=str(obligation.id),
            user_id=str(owner.id),
            assignee_membership_id=str(other_membership.id),
            expected_version=obligation.version,
        )

    same_tenant_user = User.objects.create_user(
        email='same-tenant-not-project@example.invalid',
        password='Strong-Test-Password-123!',
    )
    same_tenant_membership = OrganizationMembership.objects.create(
        organization=organization,
        user=same_tenant_user,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    with pytest.raises(AssuranceObligationError, match='member of the governed project'):
        assign_assurance_obligation(
            project_id=str(project.id),
            obligation_id=str(obligation.id),
            user_id=str(owner.id),
            assignee_membership_id=str(same_tenant_membership.id),
            expected_version=obligation.version,
        )

    obligation.refresh_from_db()
    assert obligation.assigned_to_id is not None


def test_only_assignee_can_acknowledge_and_replay_is_exact(disposition_fixture):
    owner, project, _finding, organization, _owner_membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='ack',
    )
    reviewer, reviewer_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='ack-reviewer@example.invalid',
    )
    other, _other_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='other-reviewer@example.invalid',
    )

    assigned = assign_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(owner.id),
        assignee_membership_id=str(reviewer_membership.id),
        expected_version=obligation.version,
    )
    assigned.refresh_from_db()

    with pytest.raises(PermissionError, match='currently assigned reviewer'):
        acknowledge_assurance_obligation(
            project_id=str(project.id),
            obligation_id=str(obligation.id),
            user_id=str(other.id),
            expected_version=assigned.version,
        )

    first = acknowledge_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(reviewer.id),
        expected_version=assigned.version,
    )
    first.refresh_from_db()
    first_version = first.version
    replay = acknowledge_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(reviewer.id),
        expected_version=assigned.version,
    )
    replay.refresh_from_db()

    assert replay.id == first.id
    assert replay.version == first_version
    assert replay.acknowledged_by_id == reviewer.id
    assert AssuranceObligationEvent.objects.filter(
        obligation=obligation,
        event_type=AssuranceObligationEvent.EventType.ACKNOWLEDGED,
    ).count() == 1


def test_reassignment_clears_acknowledgement_and_mine_queue_updates(disposition_fixture):
    owner, project, _finding, organization, _owner_membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='reassign',
    )
    first_user, first_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='first-reviewer@example.invalid',
    )
    second_user, second_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='second-reviewer@example.invalid',
    )

    assigned = assign_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(owner.id),
        assignee_membership_id=str(first_membership.id),
        expected_version=obligation.version,
    )
    assigned.refresh_from_db()
    acknowledged = acknowledge_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(first_user.id),
        expected_version=assigned.version,
    )
    acknowledged.refresh_from_db()

    reassigned = assign_assurance_obligation(
        project_id=str(project.id),
        obligation_id=str(obligation.id),
        user_id=str(owner.id),
        assignee_membership_id=str(second_membership.id),
        expected_version=acknowledged.version,
    )
    reassigned.refresh_from_db()

    assert reassigned.acknowledged_at is None
    assert reassigned.acknowledged_by_id is None
    assert list_review_work_queue(project_id=str(project.id), user_id=str(first_user.id), mine=True) == []
    mine = list_review_work_queue(project_id=str(project.id), user_id=str(second_user.id), mine=True)
    assert [item['id'] for item in mine] == [str(obligation.id)]


def test_work_queue_excludes_terminal_by_default(disposition_fixture):
    owner, project, _finding, _organization, _membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='terminal-queue',
    )
    obligation.status = AssuranceObligation.Status.SUPERSEDED
    obligation.superseded_at = timezone.now()
    obligation.save(update_fields=['status', 'superseded_at', 'updated_at'])

    assert list_review_work_queue(project_id=str(project.id), user_id=str(owner.id)) == []
    all_items = list_review_work_queue(
        project_id=str(project.id),
        user_id=str(owner.id),
        include_terminal=True,
    )
    assert [item['id'] for item in all_items] == [str(obligation.id)]


def test_review_work_queue_request_models_forbid_unknown_fields():
    assert AssuranceObligationAssignmentRequest.model_config.get('extra') == 'forbid'
    assert AssuranceObligationAcknowledgeRequest.model_config.get('extra') == 'forbid'
    with pytest.raises(Exception):
        AssuranceObligationAssignmentRequest(
            assignee_membership_id='00000000-0000-0000-0000-000000000001',
            expected_version=1,
            unexpected=True,
        )
    with pytest.raises(Exception):
        AssuranceObligationAcknowledgeRequest(expected_version=1, unexpected=True)


def test_postgresql_concurrent_assignment_cas_allows_one_winner(disposition_fixture):
    assert connection.vendor == 'postgresql'
    owner, project, _finding, organization, _owner_membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='concurrent-assignment',
    )
    _user_one, membership_one = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='concurrent-one@example.invalid',
    )
    _user_two, membership_two = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='concurrent-two@example.invalid',
    )
    expected = obligation.version
    barrier = Barrier(2)

    def worker(membership_id):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                result = assign_assurance_obligation(
                    project_id=str(project.id),
                    obligation_id=str(obligation.id),
                    user_id=str(owner.id),
                    assignee_membership_id=str(membership_id),
                    expected_version=expected,
                )
                return ('ok', str(result.assigned_to_id))
            except AssuranceObligationError as exc:
                return ('conflict', str(exc))
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, [membership_one.id, membership_two.id]))

    assert [item[0] for item in results].count('ok') == 1
    assert [item[0] for item in results].count('conflict') == 1
    obligation.refresh_from_db()
    assert obligation.assigned_to_id in {membership_one.id, membership_two.id}

def test_review_work_queue_http_contract_uses_governed_projection(disposition_fixture):
    client, owner, project, _asset, _authorization, _scan, _finding, organization, _membership = disposition_fixture
    _owner, _project, _finding_row, _organization, _owner_membership, _disposition_row, obligation = _materialized(
        disposition_fixture,
        marker='http-contract',
    )
    reviewer, reviewer_membership = _reviewer(
        owner=owner,
        project=project,
        organization=organization,
        email='http-queue-reviewer@example.invalid',
    )
    base = f'/api/v1/assurance/drift/projects/{project.id}'

    assigned = client.post(
        f'{base}/obligations/{obligation.id}/assign',
        json={
            'assignee_membership_id': str(reviewer_membership.id),
            'expected_version': obligation.version,
        },
    )
    assert assigned.status_code == 200, assigned.text
    payload = assigned.json()
    assert payload['assigned_to']['membership_id'] == str(reviewer_membership.id)
    assert payload['assigned_to']['user_id'] == str(reviewer.id)
    assert payload['queue_item_id'] == f'assurance-obligation:{obligation.id}'

    queue = client.get(f'{base}/work-queue')
    assert queue.status_code == 200, queue.text
    items = queue.json()['items']
    assert [item['id'] for item in items] == [str(obligation.id)]
    assert items[0]['assigned_to']['membership_id'] == str(reviewer_membership.id)

