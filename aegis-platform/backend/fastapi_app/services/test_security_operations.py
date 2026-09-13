from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone as dt_timezone
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from enterprise.models import DecisionAction, InvestigationCase, OrganizationMembership
from enterprise.soc_models import InvestigationAuditEvent, InvestigationCaseState, InvestigationSignalLink, SecuritySignal
from fastapi_app.services.detection_engineering import validate_revision
from fastapi_app.services.security_operations import (
    SecurityOperationsError,
    StaleCaseVersion,
    attach_decision_action,
    ingest_detection_signal,
    transition_case,
    verify_case_chain,
)
from fastapi_app.services.test_detection_engineering import detection_fixture, _revision, _telemetry


pytestmark = pytest.mark.django_db(transaction=True)


def _validated_revision(user, project, finding, evidence):
    revision = _revision(user, project, finding, evidence).revision
    validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id),
        telemetry=_telemetry(), minimum_matches=1,
    )
    return revision


def _ingest(user, project, revision, *, observed_at=None, event=None):
    return ingest_detection_signal(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id),
        event=event or _telemetry()[0],
        observed_at=observed_at or datetime(2026, 9, 13, 9, 30, tzinfo=dt_timezone.utc), source='siem',
    )


def test_signal_exact_replay_correlates_one_case(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    first = _ingest(user, project, revision)
    second = _ingest(user, project, revision)
    assert first.replayed is False and first.case_created is True
    assert second.replayed is True and second.case_created is False
    assert first.signal.id == second.signal.id
    assert first.case.id == second.case.id
    assert SecuritySignal.objects.count() == 1
    assert InvestigationCase.objects.filter(project=project).count() == 1
    assert InvestigationSignalLink.objects.filter(case=first.case).count() == 1
    assert verify_case_chain(case_id=str(first.case.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True


def test_non_matching_telemetry_is_rejected(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    with pytest.raises(SecurityOperationsError, match='does not satisfy'):
        _ingest(user, project, revision, event={'process': {'name': 'notepad.exe', 'command_line': 'notepad.exe'}})
    assert SecuritySignal.objects.count() == 0


def test_case_transition_uses_compare_and_swap_version(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    result = _ingest(user, project, revision)
    state = transition_case(
        case_id=str(result.case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=1, status=InvestigationCase.Status.INVESTIGATING,
    )
    assert state.version == 2
    with pytest.raises(StaleCaseVersion, match='current version is 2'):
        transition_case(
            case_id=str(result.case.id), project_id=str(project.id), user_id=str(user.id),
            expected_version=1, status=InvestigationCase.Status.DECIDED,
        )
    state = transition_case(
        case_id=str(result.case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=2, status=InvestigationCase.Status.DECIDED, decision_summary='Escalate to response.',
    )
    assert state.version == 3


def test_closed_case_creates_new_generation(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    first = _ingest(user, project, revision)
    transition_case(case_id=str(first.case.id), project_id=str(project.id), user_id=str(user.id), expected_version=1, status=InvestigationCase.Status.INVESTIGATING)
    transition_case(case_id=str(first.case.id), project_id=str(project.id), user_id=str(user.id), expected_version=2, status=InvestigationCase.Status.CLOSED)
    second = _ingest(
        user, project, revision,
        observed_at=datetime(2026, 9, 13, 9, 31, tzinfo=dt_timezone.utc),
    )
    assert second.case_created is True
    assert second.case.id != first.case.id
    assert second.state.generation == 2
    assert InvestigationCaseState.objects.filter(base_correlation_key=first.state.base_correlation_key).count() == 2


def test_audit_and_signal_evidence_are_immutable(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    result = _ingest(user, project, revision)
    with pytest.raises(ValidationError):
        SecuritySignal.objects.filter(pk=result.signal.id).update(severity='low')
    with pytest.raises(ValidationError):
        SecuritySignal.objects.bulk_create([])
    event = InvestigationAuditEvent.objects.filter(case=result.case).first()
    with pytest.raises(ValidationError):
        event.delete()
    verification = verify_case_chain(case_id=str(result.case.id), project_id=str(project.id), user_id=str(user.id))
    assert verification['valid'] is True and verification['entries'] == 2


def test_viewer_can_read_but_cannot_ingest(detection_fixture):
    _client, user, project, finding, evidence, _organization, membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    membership.role = OrganizationMembership.Role.VIEWER
    membership.save(update_fields=['role'])
    with pytest.raises(PermissionError, match='does not permit'):
        _ingest(user, project, revision)


def test_response_handoff_reuses_existing_decision_action(detection_fixture):
    _client, user, project, finding, evidence, organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    result = _ingest(user, project, revision)
    now = timezone.now()
    action = DecisionAction.objects.create(
        action_id='soc-response-action-0001', organization=organization, project=project,
        decision_id='soc-decision', node_id='finding:' + str(finding.id), title='Contain detection incident',
        owner=str(user.id), requested_by=str(user.id), sla_hours=4, state='pending',
        risk_before=90, confidence_before=95, priority=95, recommended_action='Contain and revalidate',
        remediation_plan=[], created_at=now, updated_at=now,
    )
    state, replayed = attach_decision_action(
        case_id=str(result.case.id), action_id=action.action_id, project_id=str(project.id),
        user_id=str(user.id), expected_version=1,
    )
    assert replayed is False
    assert state.decision_action_id == action.action_id
    assert state.version == 2
    state2, replayed2 = attach_decision_action(
        case_id=str(result.case.id), action_id=action.action_id, project_id=str(project.id),
        user_id=str(user.id), expected_version=2,
    )
    assert replayed2 is True and state2.version == 2


def test_postgresql_concurrent_exact_replay_serializes(detection_fixture):
    assert connection.vendor == 'postgresql'
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    barrier = Barrier(2)
    observed = datetime(2026, 9, 13, 9, 32, tzinfo=dt_timezone.utc)
    user_id, project_id, revision_id = str(user.id), str(project.id), str(revision.id)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return ingest_detection_signal(
                revision_id=revision_id, project_id=project_id, user_id=user_id,
                event=_telemetry()[0], observed_at=observed, source='siem',
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.signal.id for result in results}) == 1
    assert len({result.case.id for result in results}) == 1
    assert SecuritySignal.objects.count() == 1
    assert InvestigationCase.objects.filter(project=project).count() == 1
