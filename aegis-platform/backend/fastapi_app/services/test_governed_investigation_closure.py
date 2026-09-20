from __future__ import annotations

from uuid import uuid4

import pytest

from django_project.audit.models import AuditLog
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.models import OrganizationMembership
from enterprise.soc_models import InvestigationClosure
from fastapi_app.services.governed_action_executor import GovernedActionBlocked, execute_governed_action
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.security_operations import attach_decision_action, verify_case_chain
from fastapi_app.services.soc_closure_governance import close_investigation_case
from fastapi_app.services.test_finding_disposition import disposition_fixture, _other_finding
from fastapi_app.services.test_finding_governed_actions import _actor, _ownerize, _validation
from fastapi_app.services.test_governed_finding_dispositions import _execute_requested
from fastapi_app.services.test_soc_closure_governance import _action, _case, _verified_validation


pytestmark = pytest.mark.django_db(transaction=True)


def _closure_approver(*, owner, project, organization, marker: str):
    user, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email=f'a3-soc-approver-{marker}@example.invalid',
        role=OrganizationMembership.Role.MANAGER,
        responsibility='soc_closure_approver',
    )
    return user


def _request(*, project, proposer, case, state, parameters, marker: str):
    return create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(proposer.id),
        action_id='investigation.close',
        entity_type='investigation_case',
        entity_id=str(case.id),
        expected_version=state.version,
        idempotency_key=f'a3-investigation-request-{marker}',
        parameters=parameters,
    ).request


def test_soc_closure_api_submits_immutable_governed_request(disposition_fixture):
    client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    action = _action(owner, project, organization, finding)
    state, replayed = attach_decision_action(
        case_id=str(case.id),
        action_id=action.action_id,
        project_id=str(project.id),
        user_id=str(owner.id),
        expected_version=state.version,
    )
    assert replayed is False
    validation, _evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    request_id = uuid4()
    body = {
        'expected_version': state.version,
        'finding_id': str(finding.id),
        'closure_type': 'remediated',
        'validation_id': str(validation.id),
        'rationale': 'SOC closure endpoint submits an immutable governed proposal.',
    }

    first = client.post(
        f'/api/v1/investigation/soc/projects/{project.id}/cases/{case.id}/closure',
        json=body,
        headers={'X-Request-ID': str(request_id)},
    )
    assert first.status_code == 202, first.text
    payload = first.json()
    assert payload['action_id'] == 'investigation.close'
    assert payload['entity_type'] == 'investigation_case'
    assert payload['entity_id'] == str(case.id)
    assert payload['expected_version'] == state.version
    assert payload['parameters'] == {
        'finding_id': str(finding.id),
        'closure_type': 'remediated',
        'rationale': body['rationale'],
        'validation_id': str(validation.id),
    }
    assert payload['replayed'] is False
    row = GovernedActionRequest.objects.get(pk=payload['request_id'])
    assert row.requested_by_id == owner.id
    assert row.correlation_id == request_id
    assert not InvestigationClosure.objects.filter(case=case).exists()
    case.refresh_from_db()
    assert case.status != 'closed'

    second = client.post(
        f'/api/v1/investigation/soc/projects/{project.id}/cases/{case.id}/closure',
        json=body,
        headers={'X-Request-ID': str(request_id)},
    )
    assert second.status_code == 202, second.text
    assert second.json()['request_id'] == payload['request_id']
    assert second.json()['replayed'] is True
    assert GovernedActionRequest.objects.filter(
        action_id='investigation.close',
        entity_id=str(case.id),
    ).count() == 1
    assert not InvestigationClosure.objects.filter(case=case).exists()


def test_remediated_investigation_closure_is_request_bound_and_evidence_qualified(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    action = _action(owner, project, organization, finding)
    state, replayed = attach_decision_action(
        case_id=str(case.id),
        action_id=action.action_id,
        project_id=str(project.id),
        user_id=str(owner.id),
        expected_version=state.version,
    )
    assert replayed is False
    validation, evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    finding.refresh_from_db()
    before_finding_status = finding.status
    approver = _closure_approver(owner=owner, project=project, organization=organization, marker='remediated')
    parameters = {
        'finding_id': str(finding.id),
        'closure_type': 'remediated',
        'rationale': 'Independent governed closure after verified remediation.',
        'validation_id': str(validation.id),
    }
    request = _request(
        project=project,
        proposer=owner,
        case=case,
        state=state,
        parameters=parameters,
        marker='remediated',
    )

    result = execute_governed_action(
        action_id='investigation.close',
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='investigation_case',
        entity_id=str(case.id),
        expected_version=state.version,
        idempotency_key='a3-investigation-execution-remediated',
        request_id=str(request.id),
        parameters=parameters,
    )

    case.refresh_from_db()
    finding.refresh_from_db()
    validation.refresh_from_db()
    assert case.status == 'closed'
    assert finding.status == before_finding_status
    assert validation.result['remediation_state'] == 'verified'
    assert result.execution.request_id == request.id
    assert result.execution.result_payload['closure_type'] == 'remediated'
    assert result.execution.result_payload['evidence_id'] == str(evidence.id)
    assert result.execution.result_payload['evidence_qualification']['decision'] == 'qualified'
    assert InvestigationClosure.objects.filter(case=case, evidence=evidence).count() == 1
    assert AuditLog.objects.filter(
        metadata__governed_action_id='investigation.close',
        resource_id=str(case.id),
    ).count() == 1
    assert verify_case_chain(case_id=str(case.id), project_id=str(project.id), user_id=str(owner.id))['valid'] is True


def test_investigation_disposition_closure_requires_governed_disposition_provenance(disposition_fixture):
    _client, owner, project, asset, _authorization, scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    target = _other_finding(
        user=owner,
        project=project,
        asset=asset,
        scan=scan,
        title='A3 investigation duplicate target',
    )
    disposition_parameters = {
        'rationale': 'Governed duplicate proof for investigation closure.',
        'duplicate_of_id': str(target.id),
    }
    _p, _a, _req, disposition_execution = _execute_requested(
        action_id='finding.disposition.duplicate',
        project=project,
        finding=finding,
        organization=organization,
        owner=owner,
        parameters=disposition_parameters,
        marker='investigation-duplicate',
    )
    disposition_id = disposition_execution.execution.result_payload['disposition_id']
    approver = _closure_approver(owner=owner, project=project, organization=organization, marker='duplicate')
    parameters = {
        'finding_id': str(finding.id),
        'closure_type': 'duplicate',
        'rationale': 'Close investigation using governed duplicate disposition.',
        'disposition_id': disposition_id,
    }
    request = _request(
        project=project,
        proposer=owner,
        case=case,
        state=state,
        parameters=parameters,
        marker='duplicate',
    )

    result = execute_governed_action(
        action_id='investigation.close',
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='investigation_case',
        entity_id=str(case.id),
        expected_version=state.version,
        idempotency_key='a3-investigation-execution-duplicate',
        request_id=str(request.id),
        parameters=parameters,
    )

    assert result.execution.result_payload['disposition_id'] == disposition_id
    assert result.execution.result_payload.get('evidence_qualification') is None
    assert InvestigationClosure.objects.filter(case=case, disposition_id=disposition_id).count() == 1


def test_investigation_closure_self_approval_is_blocked(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    action = _action(owner, project, organization, finding)
    state, _ = attach_decision_action(
        case_id=str(case.id),
        action_id=action.action_id,
        project_id=str(project.id),
        user_id=str(owner.id),
        expected_version=state.version,
    )
    validation, _evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    approver = _closure_approver(owner=owner, project=project, organization=organization, marker='self')
    parameters = {
        'finding_id': str(finding.id),
        'closure_type': 'remediated',
        'rationale': 'Self approval must fail.',
        'validation_id': str(validation.id),
    }
    request = _request(
        project=project,
        proposer=approver,
        case=case,
        state=state,
        parameters=parameters,
        marker='self',
    )
    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='investigation.close',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='investigation_case',
            entity_id=str(case.id),
            expected_version=state.version,
            idempotency_key='a3-investigation-execution-self',
            request_id=str(request.id),
            parameters=parameters,
        )
    assert blocked.value.reason_code == 'SOD_VIOLATION'
    assert InvestigationClosure.objects.filter(case=case).count() == 0


def test_legacy_disposition_without_agom_execution_cannot_close_investigation(disposition_fixture):
    _client, owner, project, asset, _authorization, scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    target = _other_finding(user=owner, project=project, asset=asset, scan=scan, title='Legacy duplicate target')
    from fastapi_app.services.finding_disposition import govern_finding_disposition
    legacy = govern_finding_disposition(
        finding_id=finding.id,
        disposition='duplicate',
        rationale='Legacy direct disposition.',
        actor_id=owner.id,
        duplicate_of_id=target.id,
    ).disposition
    approver = _closure_approver(owner=owner, project=project, organization=organization, marker='legacy')
    parameters = {
        'finding_id': str(finding.id),
        'closure_type': 'duplicate',
        'rationale': 'Legacy disposition must not authorize AGOM closure.',
        'disposition_id': str(legacy.id),
    }
    request = _request(
        project=project,
        proposer=owner,
        case=case,
        state=state,
        parameters=parameters,
        marker='legacy',
    )
    with pytest.raises(GovernedActionBlocked):
        execute_governed_action(
            action_id='investigation.close',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='investigation_case',
            entity_id=str(case.id),
            expected_version=state.version,
            idempotency_key='a3-investigation-execution-legacy',
            request_id=str(request.id),
            parameters=parameters,
        )
    assert InvestigationClosure.objects.filter(case=case).count() == 0


def test_investigation_remediated_closure_rejects_non_latest_validation(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    case, state = _case(owner, project, organization, finding)
    action = _action(owner, project, organization, finding)
    state, _ = attach_decision_action(
        case_id=str(case.id),
        action_id=action.action_id,
        project_id=str(project.id),
        user_id=str(owner.id),
        expected_version=state.version,
    )
    older, _older_evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    _newer, _newer_evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    approver = _closure_approver(
        owner=owner,
        project=project,
        organization=organization,
        marker='non-latest',
    )
    parameters = {
        'finding_id': str(finding.id),
        'closure_type': 'remediated',
        'rationale': 'Older validation must not authorize closure.',
        'validation_id': str(older.id),
    }
    request = _request(
        project=project,
        proposer=owner,
        case=case,
        state=state,
        parameters=parameters,
        marker='non-latest',
    )
    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='investigation.close',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='investigation_case',
            entity_id=str(case.id),
            expected_version=state.version,
            idempotency_key='a3-investigation-execution-non-latest',
            request_id=str(request.id),
            parameters=parameters,
        )
    assert blocked.value.reason_code == 'EVIDENCE_NOT_READY'
    assert 'response_evidence' in blocked.value.missing_requirements
    assert InvestigationClosure.objects.filter(case=case).count() == 0
