from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.evidence.models import Evidence
from enterprise.assurance_obligation_models import AssuranceObligation, AssuranceObligationEvent
from enterprise.models import ContinuousAssuranceExecution, ContinuousAssuranceSchedule
from fastapi_app.routers.assurance_obligations import AssuranceObligationRequest
from fastapi_app.services.assurance_drift_governance import record_assurance_observation
from fastapi_app.services.assurance_obligation_governance import (
    materialize_assurance_obligation,
    refresh_assurance_obligation,
)
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.test_finding_disposition import disposition_fixture, _risk_snapshot

pytestmark = pytest.mark.django_db(transaction=True)


def _schedule(user, project, asset, authorization, organization):
    return ContinuousAssuranceSchedule.objects.create(
        organization=organization,
        project=project,
        asset=asset,
        authorization_decision=authorization,
        scan_type='ip',
        engine='nmap',
        interval_minutes=60,
        enabled=True,
        next_run=timezone.now() + timedelta(hours=1),
        created_by=user,
    )


def _disposition(user, project, finding, marker='obligation', kind='accepted_risk', days=30):
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker=marker)
    return govern_finding_disposition(
        finding_id=finding.id,
        disposition=kind,
        rationale=f'Governed assurance review obligation {marker}.',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=timezone.now() + timedelta(days=days),
    ).disposition


def _execution(schedule, organization, project, asset, authorization, offset=1):
    when = timezone.now() + timedelta(minutes=offset)
    return ContinuousAssuranceExecution.objects.create(
        schedule=schedule,
        organization=organization,
        project=project,
        asset=asset,
        authorization_decision=authorization,
        scheduled_for=when,
        status=ContinuousAssuranceExecution.Status.COMPLETED,
        completed_at=when,
    )


def test_materialize_tracks_review_at_and_exact_replay(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    disposition = _disposition(user, project, finding)

    first = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id))
    replay = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id))

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.obligation.id == first.obligation.id
    assert first.obligation.due_at == disposition.review_at
    assert first.obligation.status == AssuranceObligation.Status.OPEN
    assert AssuranceObligationEvent.objects.filter(obligation=first.obligation, event_type='created').count() == 1


def test_review_deadline_becomes_overdue_durably(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    disposition = _disposition(user, project, finding, marker='overdue')

    result = materialize_assurance_obligation(
        project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id),
        now=disposition.review_at + timedelta(minutes=1),
    )

    assert result.obligation.status == AssuranceObligation.Status.OVERDUE
    assert AssuranceObligationEvent.objects.filter(obligation=result.obligation, event_type='overdue').count() == 1


def test_resolved_assurance_observation_satisfies_obligation(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='resolved')
    obligation = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id)).obligation
    execution = _execution(schedule, organization, project, asset, authorization)
    observation = record_assurance_observation(
        execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id),
        finding_present=False, material={'verification': 'absent'},
    ).observation

    refreshed = refresh_assurance_obligation(project_id=str(project.id), obligation_id=str(obligation.id), user_id=str(user.id))

    assert refreshed.status == AssuranceObligation.Status.SATISFIED
    assert refreshed.last_execution_id == execution.id
    assert refreshed.last_observation_id == observation.id
    assert refreshed.satisfied_at is not None
    assert AssuranceObligationEvent.objects.filter(obligation=obligation, event_type='satisfied').count() == 1


def test_present_revalidation_records_lineage_without_false_satisfaction(disposition_fixture):
    _client, user, project, asset, authorization, scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='present')
    obligation = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id)).obligation
    execution = _execution(schedule, organization, project, asset, authorization)
    evidence = Evidence.objects.create(
        scan=scan, asset=asset, finding=finding, source='assurance-obligation-reality', evidence_type='validation',
        raw_output='finding remains present under authorized assurance execution', collected_by=user,
    )
    observation = record_assurance_observation(
        execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id),
        finding_present=True, material={'verification': 'present'}, evidence_id=str(evidence.id),
    ).observation

    refreshed = refresh_assurance_obligation(project_id=str(project.id), obligation_id=str(obligation.id), user_id=str(user.id))

    assert refreshed.status == AssuranceObligation.Status.OPEN
    assert refreshed.last_observation_id == observation.id
    assert refreshed.satisfied_at is None
    assert AssuranceObligationEvent.objects.filter(obligation=obligation, event_type='revalidated_present').count() == 1


def test_fresh_governed_disposition_supersedes_old_obligation_and_increments_generation(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='first')
    first = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id)).obligation
    _disposition(user, project, finding, marker='second', kind='wont_fix', days=45)

    second = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id)).obligation
    first.refresh_from_db()

    assert first.status == AssuranceObligation.Status.SUPERSEDED
    assert first.superseded_at is not None
    assert second.generation == 2
    assert second.id != first.id
    assert AssuranceObligationEvent.objects.filter(obligation=first, event_type='superseded').count() == 1


def test_obligation_event_is_append_only_and_bulk_bypass_is_blocked(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='immutable')
    obligation = materialize_assurance_obligation(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id)).obligation
    event = AssuranceObligationEvent.objects.get(obligation=obligation, event_type='created')
    event.payload = {'tampered': True}
    with pytest.raises(ValidationError):
        event.save()
    with pytest.raises(ValidationError):
        AssuranceObligationEvent.objects.filter(pk=event.pk).update(payload={})
    with pytest.raises(ValidationError):
        AssuranceObligationEvent.objects.bulk_create([])


def test_request_contract_forbids_unknown_fields():
    assert AssuranceObligationRequest.model_config.get('extra') == 'forbid'
    with pytest.raises(Exception):
        AssuranceObligationRequest(unexpected=True)


def test_postgresql_concurrent_materialization_serializes_to_one_obligation(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='concurrent')
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return materialize_assurance_obligation(
                project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id),
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))

    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.obligation.id for result in results}) == 1
    assert AssuranceObligation.objects.filter(disposition__finding=finding).count() == 1
