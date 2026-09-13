from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone as dt_timezone
from threading import Barrier

import pytest
from django.db import close_old_connections, connection
from django.utils import timezone

from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import DecisionAction, InvestigationCase
from enterprise.soc_models import InvestigationCaseState, InvestigationClosure
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state
from fastapi_app.services.security_operations import SecurityOperationsError, attach_decision_action, transition_case, verify_case_chain
from fastapi_app.services.soc_closure_governance import ClosureGovernanceError, close_investigation_case
from fastapi_app.services.test_detection_engineering import detection_fixture
from fastapi_app.services.test_finding_disposition import disposition_fixture, _risk_snapshot
from fastapi_app.services.test_security_operations import _ingest, _validated_revision

pytestmark = pytest.mark.django_db(transaction=True)


def _case(user, project, organization, finding):
    case = InvestigationCase.objects.create(
        organization=organization, project=project, owner=user,
        title='SOC governed closure reality', description='Closure proof reality case.',
    )
    case.findings.add(finding)
    state = InvestigationCaseState.objects.create(
        case=case, base_correlation_key=f'{finding.id.hex:0<64}'[:64], generation=1, version=1,
    )
    state = transition_case(
        case_id=str(case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=1, status=InvestigationCase.Status.INVESTIGATING,
    )
    return case, state


def _action(user, project, organization, finding):
    now = timezone.now()
    return DecisionAction.objects.create(
        action_id=f'closure-action-{finding.id}', organization=organization, project=project,
        decision_id='closure-decision', node_id='finding:' + str(finding.id), title='Remediate governed closure finding',
        owner=str(user.id), requested_by=str(user.id), sla_hours=4, state='pending',
        risk_before=90, confidence_before=95, priority=95,
        recommended_action='Remediate and verify before closure', remediation_plan=[], created_at=now, updated_at=now,
    )


def _verified_validation(user, finding):
    evidence = Evidence.objects.create(
        finding=finding, asset=finding.asset, scan=finding.scan, source='closure-reality',
        evidence_type='validation', raw_output='authorized validation confirms finding absent', collected_by=user,
    )
    validation = ValidationRun.objects.create(
        user=user, finding=finding, target_type='finding', target_value=str(finding.id),
        scope='soc-closure-reality', profile='full', engines=['reality'], authorized=True,
        status=ValidationRun.Status.COMPLETED, progress=100, current_phase='completed',
        completed_at=timezone.now(),
        result={
            'finding_present': False, 'evidence_id': str(evidence.id),
            'remediation_state': RemediationState.VERIFIED,
            'remediation_events': [{'from': RemediationState.VALIDATION_PASSED, 'to': RemediationState.VERIFIED}],
        },
    )
    return validation, evidence


def test_direct_close_is_forbidden(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    case, state = _case(user, project, organization, finding)
    with pytest.raises(SecurityOperationsError, match='governed closure'):
        transition_case(
            case_id=str(case.id), project_id=str(project.id), user_id=str(user.id),
            expected_version=state.version, status=InvestigationCase.Status.CLOSED,
        )
    case.refresh_from_db()
    assert case.status == InvestigationCase.Status.INVESTIGATING


def test_remediated_closure_requires_verified_lineage_and_closes_finding(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    case, state = _case(user, project, organization, finding)
    action = _action(user, project, organization, finding)
    state, replayed = attach_decision_action(
        case_id=str(case.id), action_id=action.action_id, project_id=str(project.id),
        user_id=str(user.id), expected_version=state.version,
    )
    assert replayed is False
    validation, evidence = _verified_validation(user, finding)

    result = close_investigation_case(
        case_id=str(case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=state.version, finding_id=str(finding.id), closure_type='remediated',
        validation_id=str(validation.id), rationale='Verified fix closes the incident.',
    )
    assert result.replayed is False
    assert result.closure.evidence_id == evidence.id
    assert result.closure.decision_action_id == action.action_id
    case.refresh_from_db(); finding.refresh_from_db(); validation.refresh_from_db()
    assert case.status == InvestigationCase.Status.CLOSED
    assert finding.status == Vulnerability.Status.FIXED
    assert get_state(validation) == RemediationState.CLOSED
    assert verify_case_chain(case_id=str(case.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True

    replay = close_investigation_case(
        case_id=str(case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=state.version, finding_id=str(finding.id), closure_type='remediated',
        validation_id=str(validation.id), rationale='Verified fix closes the incident.',
    )
    assert replay.replayed is True and replay.closure.id == result.closure.id


def test_accepted_risk_closure_uses_latest_governed_disposition(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    case, state = _case(user, project, organization, finding)
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='closure-risk')
    disposition = govern_finding_disposition(
        finding_id=finding.id, disposition='accepted_risk', rationale='Governed risk closure.', actor_id=user.id,
        risk_correlation_id=risk.id, review_at=datetime.now(dt_timezone.utc) + timedelta(days=30),
    ).disposition
    result = close_investigation_case(
        case_id=str(case.id), project_id=str(project.id), user_id=str(user.id), expected_version=state.version,
        finding_id=str(finding.id), closure_type='accepted_risk', disposition_id=str(disposition.id),
        rationale='Risk owner accepted exposure until scheduled review.',
    )
    assert result.closure.disposition_id == disposition.id
    assert result.closure.validation_run_id is None
    case.refresh_from_db()
    assert case.status == InvestigationCase.Status.CLOSED
    assert verify_case_chain(case_id=str(case.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True


def test_governed_closed_detection_case_creates_new_generation(detection_fixture):
    _client, user, project, finding, evidence, organization, _membership = detection_fixture
    revision = _validated_revision(user, project, finding, evidence)
    first = _ingest(user, project, revision)
    state = transition_case(
        case_id=str(first.case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=1, status=InvestigationCase.Status.INVESTIGATING,
    )
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='closure-generation')
    disposition = govern_finding_disposition(
        finding_id=finding.id, disposition='accepted_risk', rationale='Generation rollover governed closure.',
        actor_id=user.id, risk_correlation_id=risk.id,
        review_at=datetime.now(dt_timezone.utc) + timedelta(days=30),
    ).disposition
    closed = close_investigation_case(
        case_id=str(first.case.id), project_id=str(project.id), user_id=str(user.id),
        expected_version=state.version, finding_id=str(finding.id), closure_type='accepted_risk',
        disposition_id=str(disposition.id), rationale='Generation rollover closure.',
    )
    assert closed.replayed is False
    second = _ingest(
        user, project, revision,
        observed_at=datetime(2026, 9, 13, 9, 31, tzinfo=dt_timezone.utc),
    )
    assert second.case_created is True
    assert second.case.id != first.case.id
    assert second.state.generation == 2
    assert InvestigationCaseState.objects.filter(base_correlation_key=first.state.base_correlation_key).count() == 2


def test_unverified_remediation_cannot_close(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    case, state = _case(user, project, organization, finding)
    action = _action(user, project, organization, finding)
    state, _ = attach_decision_action(case_id=str(case.id), action_id=action.action_id, project_id=str(project.id), user_id=str(user.id), expected_version=state.version)
    validation, _evidence = _verified_validation(user, finding)
    validation.result = {**validation.result, 'remediation_state': RemediationState.VALIDATION_PASSED}
    validation.save(update_fields=['result'])
    with pytest.raises(ClosureGovernanceError, match='VERIFIED'):
        close_investigation_case(
            case_id=str(case.id), project_id=str(project.id), user_id=str(user.id), expected_version=state.version,
            finding_id=str(finding.id), closure_type='remediated', validation_id=str(validation.id),
        )
    assert InvestigationClosure.objects.count() == 0


def test_postgresql_concurrent_identical_risk_closure_is_idempotent(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _client, user, project, _asset, _authorization, _scan, finding, organization, _membership = disposition_fixture
    case, state = _case(user, project, organization, finding)
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='closure-race')
    disposition = govern_finding_disposition(
        finding_id=finding.id, disposition='accepted_risk', rationale='Concurrent closure risk.', actor_id=user.id,
        risk_correlation_id=risk.id, review_at=datetime.now(dt_timezone.utc) + timedelta(days=30),
    ).disposition
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return close_investigation_case(
                case_id=str(case.id), project_id=str(project.id), user_id=str(user.id), expected_version=state.version,
                finding_id=str(finding.id), closure_type='accepted_risk', disposition_id=str(disposition.id),
                rationale='Concurrent governed close.',
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(result.replayed for result in results) == [False, True]
    assert len({result.closure.id for result in results}) == 1
    assert InvestigationClosure.objects.filter(case=case).count() == 1
