from __future__ import annotations

import pytest

from django_project.audit.models import AuditLog
from django_project.evidence.models import FindingConfirmation
from django_project.vulnerabilities.models import Vulnerability
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.models import OrganizationMembership
from fastapi_app.services.governed_action_executor import (
    GovernedActionConflict,
    GovernedActionError,
    execute_governed_action,
)
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_finding_governed_actions import _actor, _ownerize, _validation


pytestmark = pytest.mark.django_db(transaction=True)


def _setup(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    confirmer, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='a3-false-positive@example.invalid',
        role=OrganizationMembership.Role.ANALYST,
        responsibility='finding_confirmer',
    )
    validation, evidence = _validation(
        user=confirmer,
        finding=finding,
        authorization=authorization,
        finding_present=False,
    )
    parameters = {
        'validation_id': str(validation.id),
        'rationale': 'Independent validation proves the finding is absent.',
    }
    request = create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(confirmer.id),
        action_id='finding.false_positive',
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key='a3-false-positive-request-0001',
        parameters=parameters,
    ).request
    return project, finding, confirmer, validation, evidence, request, parameters


def test_false_positive_api_submits_governed_request_without_classification(disposition_fixture):
    client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    validator, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='a3-false-positive-api-validator@example.invalid',
        role=OrganizationMembership.Role.ANALYST,
        responsibility='finding_confirmer',
    )
    validation, _evidence = _validation(
        user=validator,
        finding=finding,
        authorization=authorization,
        finding_present=False,
    )
    body = {
        'validation_id': str(validation.id),
        'verdict': 'false_positive',
        'rationale': 'API false-positive proposal remains immutable before governed execution.',
        'expected_version': finding.version,
        'idempotency_key': 'a3-false-positive-api-proposal-0001',
    }

    first = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=body,
    )
    assert first.status_code == 202, first.text
    payload = first.json()
    assert payload['action_id'] == 'finding.false_positive'
    assert payload['entity_type'] == 'finding'
    assert payload['entity_id'] == str(finding.id)
    assert payload['expected_version'] == finding.version
    assert payload['parameters'] == {
        'validation_id': str(validation.id),
        'rationale': body['rationale'],
    }
    assert payload['replayed'] is False
    assert GovernedActionRequest.objects.filter(pk=payload['request_id']).exists()
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert not FindingConfirmation.objects.filter(finding=finding).exists()

    replay = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=body,
    )
    assert replay.status_code == 202, replay.text
    assert replay.json()['request_id'] == payload['request_id']
    assert replay.json()['replayed'] is True
    assert GovernedActionRequest.objects.filter(
        action_id='finding.false_positive',
        entity_id=str(finding.id),
    ).count() == 1
    assert not FindingConfirmation.objects.filter(finding=finding).exists()


def test_false_positive_executes_only_through_request_bound_agom(disposition_fixture):
    project, finding, confirmer, validation, evidence, request, parameters = _setup(disposition_fixture)

    result = execute_governed_action(
        action_id='finding.false_positive',
        project_id=str(project.id),
        actor_id=str(confirmer.id),
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key='a3-false-positive-execution-0001',
        request_id=str(request.id),
        parameters=parameters,
    )

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.FALSE_POSITIVE
    assert finding.validation_status == 'false_positive'
    assert finding.version == 2
    assert result.execution.request_id == request.id
    assert result.execution.result_payload['validation_id'] == str(validation.id)
    assert result.execution.result_payload['evidence_id'] == str(evidence.id)
    assert result.execution.result_payload['evidence_qualification']['decision'] == 'qualified'
    assert FindingConfirmation.objects.filter(
        finding=finding,
        validation_run=validation,
        verdict=FindingConfirmation.Verdict.FALSE_POSITIVE,
    ).count() == 1
    assert AuditLog.objects.filter(
        metadata__governed_action_id='finding.false_positive',
        resource_id=str(finding.id),
    ).count() == 1
    assert AuditLog.objects.filter(
        metadata__operation='finding_confirmation',
        resource_id=str(finding.id),
    ).count() == 0


def test_false_positive_without_request_is_fail_closed(disposition_fixture):
    project, finding, confirmer, _validation, _evidence, _request, parameters = _setup(disposition_fixture)
    with pytest.raises(GovernedActionError, match='requires an immutable request_id'):
        execute_governed_action(
            action_id='finding.false_positive',
            project_id=str(project.id),
            actor_id=str(confirmer.id),
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=finding.version,
            idempotency_key='a3-false-positive-no-request-0001',
            parameters=parameters,
        )
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.version == 1


def test_false_positive_request_cannot_be_rebound(disposition_fixture):
    project, finding, confirmer, validation, _evidence, request, parameters = _setup(disposition_fixture)
    altered = {**parameters, 'rationale': 'Changed after immutable proposal.'}
    with pytest.raises(GovernedActionConflict, match='does not match the execution command'):
        execute_governed_action(
            action_id='finding.false_positive',
            project_id=str(project.id),
            actor_id=str(confirmer.id),
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=finding.version,
            idempotency_key='a3-false-positive-rebind-0001',
            request_id=str(request.id),
            parameters=altered,
        )
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert FindingConfirmation.objects.filter(validation_run=validation).count() == 0
