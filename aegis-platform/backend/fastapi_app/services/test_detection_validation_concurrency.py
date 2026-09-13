from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import close_old_connections

from enterprise.detection_models import DetectionEvent, DetectionValidation
from fastapi_app.services.detection_engineering import create_revision, validate_revision
from fastapi_app.services.test_detection_engineering import detection_fixture, _revision, _spec, _telemetry


pytestmark = pytest.mark.django_db(transaction=True)


def _run_concurrently(calls):
    barrier = threading.Barrier(len(calls))

    def worker(call):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return call()
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=len(calls)) as pool:
        futures = [pool.submit(worker, call) for call in calls]
        return [future.result(timeout=20) for future in futures]


def test_validation_exact_replay_is_serialized_on_postgresql(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision

    def validate():
        return validate_revision(
            revision_id=str(revision.id),
            project_id=str(project.id),
            user_id=str(user.id),
            telemetry=_telemetry(),
            minimum_matches=1,
        )

    results = _run_concurrently([validate, validate])

    assert sorted(result.replayed for result in results) == [False, True]
    assert results[0].validation.id == results[1].validation.id
    assert DetectionValidation.objects.filter(revision=revision).count() == 1
    assert DetectionEvent.objects.filter(rule=revision.rule, event_type='validation.completed').count() == 1


def test_validation_event_chain_is_serialized_across_revisions(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    first = _revision(user, project, finding, evidence).revision
    second_spec = _spec()
    second_spec['description'] = 'Second revision for event-chain serialization reality.'
    second = create_revision(
        project_id=str(project.id),
        user_id=str(user.id),
        slug='encoded-powershell',
        title='Encoded PowerShell',
        description='Governed endpoint detection revision two.',
        finding_id=str(finding.id),
        evidence_id=str(evidence.id),
        spec=second_spec,
    ).revision
    assert first.id != second.id

    def validate_first():
        return validate_revision(
            revision_id=str(first.id), project_id=str(project.id), user_id=str(user.id),
            telemetry=_telemetry(), minimum_matches=1,
        )

    def validate_second():
        return validate_revision(
            revision_id=str(second.id), project_id=str(project.id), user_id=str(user.id),
            telemetry=_telemetry(), minimum_matches=1,
        )

    results = _run_concurrently([validate_first, validate_second])
    assert all(result.replayed is False for result in results)
    assert DetectionValidation.objects.filter(revision__rule=first.rule).count() == 2

    events = list(DetectionEvent.objects.filter(rule=first.rule).order_by('id'))
    assert [event.event_type for event in events].count('validation.completed') == 2
    assert events[0].payload['previous_entry_sha256'] == ''
    for previous, current in zip(events, events[1:]):
        assert current.payload['previous_entry_sha256'] == previous.entry_sha256
