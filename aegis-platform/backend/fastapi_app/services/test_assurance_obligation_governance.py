from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from enterprise.assurance_models import AssuranceObligation, AssuranceObligationEvent
from fastapi_app.routers.assurance_obligations import ObligationSatisfyIn, RecurrenceObligationIn, RiskReviewObligationIn
from fastapi_app.services.assurance_drift_governance import record_assurance_observation
from fastapi_app.services.assurance_obligation_governance import (
    AssuranceObligationError,
    evaluate_obligation_sla,
    materialize_expired_risk_obligation,
    materialize_recurrence_obligation,
    satisfy_obligation,
    verify_obligation_chain,
)
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.test_assurance_drift_governance import _evidence, _execution
from fastapi_app.services.test_finding_disposition import _risk_snapshot, disposition_fixture

pytestmark = pytest.mark.django_db(transaction=True)


def _risk_disposition(user, project, finding, review_at):
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='assurance-obligation')
    return govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='Governed temporary risk acceptance pending mandatory review.',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=review_at,
    ).disposition


def _recurrent_observation(user, project, asset, authorization, finding, organization):
    evidence = _evidence(user, finding, 'obligation-recurrence')
    first = _execution(user, project, asset, authorization, organization, 1)
    resolved_execution = _execution(user, project, asset, authorization, organization, 2)
    recurrent_execution = _execution(user, project, asset, authorization, organization, 3)
    common = dict(project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id))
    record_assurance_observation(
        execution_id=str(first.id), finding_present=True, material={'severity': 'high'}, evidence_id=str(evidence.id), **common,
    )
    record_assurance_observation(
        execution_id=str(resolved_execution.id), finding_present=False, material={'severity': 'high'}, **common,
    )
    recurrent = record_assurance_observation(
        execution_id=str(recurrent_execution.id), finding_present=True, material={'severity': 'critical'}, evidence_id=str(evidence.id), **common,
    )
    assert recurrent.observation.classification == 'recurrent'
    return recurrent.observation


def test_expired_risk_acceptance_materializes_governed_obligation(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    review_at = timezone.now() + timedelta(days=1)
    disposition = _risk_disposition(user, project, finding, review_at)
    result = materialize_expired_risk_obligation(
        disposition_id=str(disposition.id), project_id=str(project.id), user_id=str(user.id), now=review_at + timedelta(seconds=1),
    )
    assert result.replayed is False
    assert result.obligation.source_type == 'risk_review'
    assert result.obligation.source_disposition_id == disposition.id
    assert result.obligation.due_at == disposition.review_at
    assert result.obligation.status == 'open'
    assert result.obligation.policy_id
    assert verify_obligation_chain(obligation_id=str(result.obligation.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True


def test_risk_review_before_due_is_rejected(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    review_at = timezone.now() + timedelta(days=10)
    disposition = _risk_disposition(user, project, finding, review_at)
    with pytest.raises(AssuranceObligationError, match='not due'):
        materialize_expired_risk_obligation(
            disposition_id=str(disposition.id), project_id=str(project.id), user_id=str(user.id), now=review_at - timedelta(days=1),
        )


def test_recurrence_creates_new_generation_and_supersedes_open_review(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    review_at = timezone.now() + timedelta(days=1)
    disposition = _risk_disposition(user, project, finding, review_at)
    risk_obligation = materialize_expired_risk_obligation(
        disposition_id=str(disposition.id), project_id=str(project.id), user_id=str(user.id), now=review_at + timedelta(seconds=1),
    ).obligation
    recurrent = _recurrent_observation(user, project, asset, authorization, finding, organization)
    recurrence = materialize_recurrence_obligation(
        observation_id=str(recurrent.id), project_id=str(project.id), user_id=str(user.id),
    ).obligation
    risk_obligation.refresh_from_db()
    assert risk_obligation.status == 'superseded'
    assert recurrence.status == 'open'
    assert recurrence.generation == risk_obligation.generation + 1
    assert recurrence.source_observation_id == recurrent.id
    assert recurrence.source_disposition_id == disposition.id


def test_obligation_sla_breach_and_resolved_observation_satisfaction(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, _membership = disposition_fixture
    recurrent = _recurrent_observation(user, project, asset, authorization, finding, organization)
    obligation = materialize_recurrence_obligation(
        observation_id=str(recurrent.id), project_id=str(project.id), user_id=str(user.id),
    ).obligation
    changed = evaluate_obligation_sla(
        project_id=str(project.id), user_id=str(user.id), now=obligation.due_at + timedelta(seconds=1),
    )
    obligation.refresh_from_db()
    assert changed and obligation.sla_status == 'breached' and obligation.escalation_level >= 2

    resolved_execution = _execution(user, project, asset, authorization, organization, 20)
    resolved = record_assurance_observation(
        execution_id=str(resolved_execution.id), project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id),
        finding_present=False, material={'severity': 'critical', 'verification': 'absent'},
    ).observation
    current_version = obligation.version
    result = satisfy_obligation(
        obligation_id=str(obligation.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=current_version, observation_id=str(resolved.id),
    )
    assert result.replayed is False
    obligation.refresh_from_db()
    assert obligation.status == 'satisfied'
    assert obligation.satisfied_observation_id == resolved.id
    replay = satisfy_obligation(
        obligation_id=str(obligation.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=current_version, observation_id=str(resolved.id),
    )
    assert replay.replayed is True
    assert verify_obligation_chain(obligation_id=str(obligation.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True


def test_obligation_event_evidence_is_append_only(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    review_at = timezone.now() + timedelta(days=1)
    disposition = _risk_disposition(user, project, finding, review_at)
    obligation = materialize_expired_risk_obligation(
        disposition_id=str(disposition.id), project_id=str(project.id), user_id=str(user.id), now=review_at + timedelta(seconds=1),
    ).obligation
    event = obligation.events.first()
    event.payload = {'tampered': True}
    with pytest.raises(ValidationError):
        event.save()
    with pytest.raises(ValidationError):
        AssuranceObligationEvent.objects.filter(pk=event.pk).update(payload={})
    with pytest.raises(ValidationError):
        AssuranceObligationEvent.objects.bulk_create([])


def test_api_contracts_forbid_unknown_fields():
    for model in (RiskReviewObligationIn, RecurrenceObligationIn, ObligationSatisfyIn):
        assert model.model_config.get('extra') == 'forbid'


def test_postgresql_concurrent_expiry_materialization_is_idempotent(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    review_at = datetime.now(dt_timezone.utc) + timedelta(days=1)
    disposition = _risk_disposition(user, project, finding, review_at)
    now = review_at + timedelta(seconds=1)
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return materialize_expired_risk_obligation(
                disposition_id=str(disposition.id), project_id=str(project.id), user_id=str(user.id), now=now,
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.obligation.id for result in results}) == 1
    assert AssuranceObligation.objects.filter(source_disposition=disposition).count() == 1
