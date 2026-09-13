from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.evidence.models import Evidence
from enterprise.assurance_models import AssuranceObservation
from enterprise.models import ContinuousAssuranceExecution, ContinuousAssuranceSchedule
from fastapi_app.routers.assurance_drift import AssuranceObservationRequest
from fastapi_app.services.assurance_drift_governance import AssuranceDriftError, record_assurance_observation
from fastapi_app.services.test_finding_disposition import disposition_fixture

pytestmark = pytest.mark.django_db(transaction=True)


def _execution(user, project, asset, authorization, organization, offset: int):
    when = timezone.now() + timedelta(minutes=offset)
    schedule = ContinuousAssuranceSchedule.objects.create(
        organization=organization,
        project=project,
        asset=asset,
        authorization_decision=authorization,
        scan_type='vulnerability',
        engine='reality',
        interval_minutes=60,
        enabled=True,
        next_run=when + timedelta(hours=1),
        created_by=user,
    )
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


def _evidence(user, finding, marker='assurance-drift'):
    return Evidence.objects.create(
        finding=finding,
        asset=finding.asset,
        scan=finding.scan,
        source='assurance-drift-reality',
        evidence_type='validation',
        raw_output=f'{marker}: governed finding present',
        collected_by=user,
    )


def test_new_stable_changed_resolved_recurrent_generation(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    evidence = _evidence(user, finding)
    executions = [_execution(user, project, asset, authorization, organization, n) for n in range(5)]
    common = dict(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id))

    first = record_assurance_observation(execution_id=str(executions[0].id), finding_present=True, material={'severity': 'high'}, evidence_id=str(evidence.id), **common)
    stable = record_assurance_observation(execution_id=str(executions[1].id), finding_present=True, material={'severity': 'high'}, evidence_id=str(evidence.id), **common)
    changed = record_assurance_observation(execution_id=str(executions[2].id), finding_present=True, material={'severity': 'critical'}, evidence_id=str(evidence.id), **common)
    resolved = record_assurance_observation(execution_id=str(executions[3].id), finding_present=False, material={'severity': 'critical'}, **common)
    recurrent = record_assurance_observation(execution_id=str(executions[4].id), finding_present=True, material={'severity': 'critical'}, evidence_id=str(evidence.id), **common)

    assert [first.observation.classification, stable.observation.classification, changed.observation.classification, resolved.observation.classification, recurrent.observation.classification] == ['new', 'stable', 'changed', 'resolved', 'recurrent']
    assert recurrent.state.generation == 2
    assert recurrent.state.state == 'active'
    assert recurrent.state.version == 5


def test_exact_replay_is_idempotent(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    evidence = _evidence(user, finding, 'replay')
    execution = _execution(user, project, asset, authorization, organization, 10)
    kwargs = dict(execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), finding_present=True, material={'severity': 'high'}, evidence_id=str(evidence.id))
    first = record_assurance_observation(**kwargs)
    replay = record_assurance_observation(**kwargs)
    assert first.replayed is False
    assert replay.replayed is True
    assert first.observation.id == replay.observation.id
    assert AssuranceObservation.objects.filter(execution=execution, finding=finding).count() == 1


def test_present_observation_requires_evidence(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    execution = _execution(user, project, asset, authorization, organization, 20)
    with pytest.raises(AssuranceDriftError, match='evidence-backed'):
        record_assurance_observation(execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), finding_present=True, material={'severity': 'high'})


def test_observation_is_append_only_and_bulk_bypass_is_blocked(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    evidence = _evidence(user, finding, 'immutable')
    execution = _execution(user, project, asset, authorization, organization, 30)
    result = record_assurance_observation(execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), finding_present=True, material={'severity': 'high'}, evidence_id=str(evidence.id))
    result.observation.payload = {'tampered': True}
    with pytest.raises(ValidationError):
        result.observation.save()
    with pytest.raises(ValidationError):
        AssuranceObservation.objects.filter(pk=result.observation.pk).update(payload={})
    with pytest.raises(ValidationError):
        AssuranceObservation.objects.bulk_create([])


def test_request_contract_forbids_unknown_fields():
    assert AssuranceObservationRequest.model_config.get('extra') == 'forbid'
    with pytest.raises(Exception):
        AssuranceObservationRequest(execution_id='00000000-0000-0000-0000-000000000001', finding_id='00000000-0000-0000-0000-000000000002', finding_present=False, material={}, unexpected=True)


def test_postgresql_concurrent_exact_replay_serializes(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    evidence = _evidence(user, finding, 'concurrency')
    execution = _execution(user, project, asset, authorization, organization, 40)
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return record_assurance_observation(
                execution_id=str(execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id),
                finding_present=True, material={'severity': 'high', 'marker': 'concurrent'}, evidence_id=str(evidence.id),
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.observation.id for result in results}) == 1
    assert AssuranceObservation.objects.filter(execution=execution, finding=finding).count() == 1
