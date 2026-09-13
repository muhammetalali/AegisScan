from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.db import close_old_connections, connection

from django_project.evidence.models import Evidence
from enterprise.assurance_models import AssuranceObservation
from enterprise.assurance_obligation_models import AssuranceObligation, AssuranceObligationEvent
from fastapi_app.services import assurance_obligation_governance as obligation_service
from fastapi_app.services.assurance_drift_governance import record_assurance_observation
from fastapi_app.services.assurance_obligation_governance import (
    materialize_assurance_obligation,
    materialize_recurrence_obligation,
    refresh_assurance_obligation,
)
from fastapi_app.services.test_assurance_obligation_governance import _disposition, _execution, _schedule
from fastapi_app.services.test_finding_disposition import disposition_fixture

pytestmark = pytest.mark.django_db(transaction=True)


def _evidence(*, user, scan, asset, finding, marker):
    return Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=finding,
        source='assurance-recurrence-obligation-reality',
        evidence_type='validation',
        raw_output=f'governed recurrence evidence {marker}',
        collected_by=user,
    )


def _record_recurrence_sequence(*, user, project, asset, authorization, scan, finding, organization, schedule, marker='auto'):
    evidence = _evidence(user=user, scan=scan, asset=asset, finding=finding, marker=marker)
    first = _execution(schedule, organization, project, asset, authorization, offset=1)
    resolved = _execution(schedule, organization, project, asset, authorization, offset=2)
    recurrent_execution = _execution(schedule, organization, project, asset, authorization, offset=3)
    common = dict(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id))
    record_assurance_observation(
        execution_id=str(first.id), finding_present=True, material={'severity': 'high', 'marker': marker}, evidence_id=str(evidence.id), **common,
    )
    record_assurance_observation(
        execution_id=str(resolved.id), finding_present=False, material={'severity': 'high', 'marker': marker}, **common,
    )
    result = record_assurance_observation(
        execution_id=str(recurrent_execution.id), finding_present=True, material={'severity': 'critical', 'marker': marker}, evidence_id=str(evidence.id), **common,
    )
    assert result.observation.classification == AssuranceObservation.Classification.RECURRENT
    return result.observation


def test_recurrence_auto_materializes_new_generation_and_supersedes_review(disposition_fixture):
    _client, user, project, asset, authorization, scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    disposition = _disposition(user, project, finding, marker='recurrence-auto')
    review = materialize_assurance_obligation(
        project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id),
    ).obligation

    recurrent = _record_recurrence_sequence(
        user=user, project=project, asset=asset, authorization=authorization, scan=scan, finding=finding,
        organization=organization, schedule=schedule,
    )

    review.refresh_from_db()
    recurrence = AssuranceObligation.objects.get(source_observation=recurrent)
    assert review.status == AssuranceObligation.Status.SUPERSEDED
    assert review.superseded_at is not None
    assert recurrence.kind == AssuranceObligation.Kind.RECURRENCE_REVIEW
    assert recurrence.status == AssuranceObligation.Status.OPEN
    assert recurrence.generation == review.generation + 1
    assert recurrence.disposition_id is None
    assert recurrence.source_disposition_id == disposition.id
    assert recurrence.schedule_id == schedule.id
    assert recurrence.due_at > recurrent.observed_at
    assert AssuranceObligationEvent.objects.filter(obligation=recurrence, event_type=AssuranceObligationEvent.EventType.CREATED).count() == 1

    replay = materialize_recurrence_obligation(
        project_id=str(project.id), observation_id=str(recurrent.id), user_id=str(user.id),
    )
    assert replay.replayed is True
    assert replay.obligation.id == recurrence.id
    assert AssuranceObligationEvent.objects.filter(obligation=recurrence, event_type=AssuranceObligationEvent.EventType.CREATED).count() == 1


def test_resolved_observation_satisfies_recurrence_obligation(disposition_fixture):
    _client, user, project, asset, authorization, scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='recurrence-resolved')
    recurrent = _record_recurrence_sequence(
        user=user, project=project, asset=asset, authorization=authorization, scan=scan, finding=finding,
        organization=organization, schedule=schedule, marker='resolved',
    )
    recurrence = AssuranceObligation.objects.get(source_observation=recurrent)

    resolved_execution = _execution(schedule, organization, project, asset, authorization, offset=20)
    resolved = record_assurance_observation(
        execution_id=str(resolved_execution.id),
        project_id=str(project.id),
        finding_id=str(finding.id),
        user_id=str(user.id),
        finding_present=False,
        material={'verification': 'absent-after-recurrence'},
    ).observation
    refreshed = refresh_assurance_obligation(
        project_id=str(project.id), obligation_id=str(recurrence.id), user_id=str(user.id),
    )

    assert resolved.classification == AssuranceObservation.Classification.RESOLVED
    assert refreshed.status == AssuranceObligation.Status.SATISFIED
    assert refreshed.last_observation_id == resolved.id
    assert refreshed.last_execution_id == resolved_execution.id
    assert refreshed.satisfied_at == resolved.observed_at
    assert AssuranceObligationEvent.objects.filter(obligation=recurrence, event_type=AssuranceObligationEvent.EventType.SATISFIED).count() == 1


def test_postgresql_concurrent_recurrence_materialization_is_exact_replay(disposition_fixture, monkeypatch):
    assert connection.vendor == 'postgresql'
    _client, user, project, asset, authorization, scan, finding, organization, _membership = disposition_fixture
    schedule = _schedule(user, project, asset, authorization, organization)
    _disposition(user, project, finding, marker='recurrence-concurrency')

    original = obligation_service.materialize_recurrence_obligation
    monkeypatch.setattr(obligation_service, 'materialize_recurrence_obligation', lambda **_kwargs: None)
    recurrent = _record_recurrence_sequence(
        user=user, project=project, asset=asset, authorization=authorization, scan=scan, finding=finding,
        organization=organization, schedule=schedule, marker='concurrency',
    )
    monkeypatch.setattr(obligation_service, 'materialize_recurrence_obligation', original)
    assert not AssuranceObligation.objects.filter(source_observation=recurrent).exists()

    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return materialize_recurrence_obligation(
                project_id=str(project.id), observation_id=str(recurrent.id), user_id=str(user.id),
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))

    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.obligation.id for result in results}) == 1
    assert AssuranceObligation.objects.filter(source_observation=recurrent).count() == 1
    obligation = results[0].obligation
    assert AssuranceObligationEvent.objects.filter(obligation=obligation, event_type=AssuranceObligationEvent.EventType.CREATED).count() == 1
