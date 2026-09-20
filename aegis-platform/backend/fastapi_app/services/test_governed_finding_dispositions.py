from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from django_project.audit.models import AuditLog
from django_project.evidence.models import FindingDisposition
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.models import OrganizationMembership
from fastapi_app.services.governed_action_executor import (
    GovernedActionBlocked,
    GovernedActionConflict,
    execute_governed_action,
)
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.test_finding_disposition import (
    _other_finding,
    _risk_snapshot,
    disposition_fixture,  # noqa: F401
)
from fastapi_app.services.test_finding_governed_actions import (
    _actor,
    _confirmation_request,
)


pytestmark = pytest.mark.django_db(transaction=True)


def _proposer(*, project, organization, marker: str):
    user = User.objects.create_user(
        email=f'a3-proposer-{marker}@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='A3',
        last_name='Proposer',
    )
    project.members.add(user)
    OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    return user


def _approver(*, owner, project, organization, marker: str):
    user, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email=f'a3-approver-{marker}@example.invalid',
        role=OrganizationMembership.Role.MANAGER,
        responsibility='risk_approver',
    )
    return user


def _confirmed(disposition_fixture):
    (
        owner,
        project,
        authorization,
        finding,
        organization,
        _owner_membership,
        _confirmer,
        _validation,
        _evidence,
        confirm_kwargs,
    ) = _confirmation_request(disposition_fixture)
    execute_governed_action(**confirm_kwargs)
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.CONFIRMED
    return owner, project, authorization, finding, organization


def _execute_requested(
    *,
    action_id: str,
    project,
    finding,
    organization,
    owner,
    parameters: dict,
    marker: str,
):
    proposer = _proposer(project=project, organization=organization, marker=marker)
    approver = _approver(owner=owner, project=project, organization=organization, marker=marker)
    request = create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(proposer.id),
        action_id=action_id,
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key=f'a3-request-{marker}-0001',
        parameters=parameters,
    ).request
    result = execute_governed_action(
        action_id=action_id,
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key=f'a3-execution-{marker}-0001',
        request_id=str(request.id),
        parameters=parameters,
    )
    return proposer, approver, request, result


@pytest.mark.parametrize(
    ('action_id', 'disposition'),
    [
        ('finding.disposition.accept_risk', FindingDisposition.Disposition.ACCEPTED_RISK),
        ('finding.disposition.wont_fix', FindingDisposition.Disposition.WONT_FIX),
    ],
)
def test_risk_dispositions_execute_through_request_sod_and_temporal_policy(
    disposition_fixture,
    action_id,
    disposition,
):
    owner, project, _authorization, finding, organization = _confirmed(disposition_fixture)
    risk = _risk_snapshot(
        user=owner,
        project=project,
        finding=finding,
        marker=f'a3-{disposition}',
    )
    parameters = {
        'rationale': f'Governed {disposition} business decision.',
        'risk_correlation_id': str(risk.id),
        'review_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    _proposer_user, _approver_user, request, result = _execute_requested(
        action_id=action_id,
        project=project,
        finding=finding,
        organization=organization,
        owner=owner,
        parameters=parameters,
        marker=disposition,
    )

    finding.refresh_from_db()
    row = FindingDisposition.objects.get(finding=finding)
    assert finding.status == disposition
    assert finding.version == 3
    assert row.risk_correlation_id == risk.id
    assert result.execution.request_id == request.id
    assert result.execution.result_payload['disposition'] == disposition
    assert result.execution.result_payload['temporal_policy']['allowed'] is True
    assert AuditLog.objects.filter(
        metadata__governed_action_id=action_id,
        resource_id=str(finding.id),
    ).count() == 1
    assert AuditLog.objects.filter(
        metadata__operation='finding_disposition',
        resource_id=str(finding.id),
    ).count() == 0


def test_duplicate_executes_through_request_sod_and_canonical_domain_validation(disposition_fixture):
    _client, owner, project, asset, _authorization, scan, finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    duplicate_target = _other_finding(
        user=owner,
        project=project,
        asset=asset,
        scan=scan,
        title='A3 canonical duplicate target',
    )
    parameters = {
        'rationale': 'Duplicate confirmed by governed triage.',
        'duplicate_of_id': str(duplicate_target.id),
    }
    _proposer_user, _approver_user, request, result = _execute_requested(
        action_id='finding.disposition.duplicate',
        project=project,
        finding=finding,
        organization=organization,
        owner=owner,
        parameters=parameters,
        marker='duplicate',
    )

    finding.refresh_from_db()
    row = FindingDisposition.objects.get(finding=finding)
    assert finding.status == Vulnerability.Status.DUPLICATE
    assert finding.duplicate_of_id == duplicate_target.id
    assert finding.version == 2
    assert row.duplicate_of_id == duplicate_target.id
    assert result.execution.request_id == request.id
    assert AuditLog.objects.filter(
        metadata__governed_action_id='finding.disposition.duplicate',
        resource_id=str(finding.id),
    ).count() == 1
    assert AuditLog.objects.filter(
        metadata__operation='finding_disposition',
        resource_id=str(finding.id),
    ).count() == 0


def test_disposition_proposer_cannot_approve_own_request(disposition_fixture):
    owner, project, _authorization, finding, organization = _confirmed(disposition_fixture)
    risk = _risk_snapshot(
        user=owner,
        project=project,
        finding=finding,
        marker='a3-sod',
    )
    approver = _approver(owner=owner, project=project, organization=organization, marker='self')
    parameters = {
        'rationale': 'Self approval must be blocked.',
        'risk_correlation_id': str(risk.id),
        'review_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    request = create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(approver.id),
        action_id='finding.disposition.accept_risk',
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key='a3-self-request-0001',
        parameters=parameters,
    ).request

    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='finding.disposition.accept_risk',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=finding.version,
            idempotency_key='a3-self-execution-0001',
            request_id=str(request.id),
            parameters=parameters,
        )
    assert blocked.value.reason_code == 'SOD_VIOLATION'
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.CONFIRMED
    assert FindingDisposition.objects.filter(finding=finding).count() == 0


def test_governed_request_is_single_consumption(disposition_fixture):
    _client, owner, project, asset, _authorization, scan, finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    target = _other_finding(user=owner, project=project, asset=asset, scan=scan, title='Single consume target')
    parameters = {'rationale': 'Single consumption request.', 'duplicate_of_id': str(target.id)}
    _proposer_user, approver, request, _first = _execute_requested(
        action_id='finding.disposition.duplicate',
        project=project,
        finding=finding,
        organization=organization,
        owner=owner,
        parameters=parameters,
        marker='single-consume',
    )

    with pytest.raises(GovernedActionConflict, match='already been consumed'):
        execute_governed_action(
            action_id='finding.disposition.duplicate',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=1,
            idempotency_key='a3-second-execution-0001',
            request_id=str(request.id),
            parameters=parameters,
        )


def test_accepted_risk_api_maps_to_canonical_governed_action_without_domain_mutation(disposition_fixture):
    client, _owner, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    request_id = uuid4()
    risk_correlation_id = uuid4()
    review_at = datetime.now(timezone.utc) + timedelta(days=30)
    body = {
        'disposition': 'accepted_risk',
        'rationale': 'Accepted risk proposal must resolve to the canonical governed action id.',
        'risk_correlation_id': str(risk_correlation_id),
        'review_at': review_at.isoformat(),
    }

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/dispositions',
        json=body,
        headers={'X-Request-ID': str(request_id)},
    )
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload['action_id'] == 'finding.disposition.accept_risk'
    assert payload['entity_type'] == 'finding'
    assert payload['entity_id'] == str(finding.id)
    assert payload['expected_version'] == finding.version
    assert payload['parameters']['risk_correlation_id'] == str(risk_correlation_id)
    assert payload['replayed'] is False
    assert GovernedActionRequest.objects.filter(
        action_id='finding.disposition.accept_risk',
        entity_id=str(finding.id),
    ).count() == 1
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert not FindingDisposition.objects.filter(finding=finding).exists()


def test_disposition_api_submits_immutable_governed_request_without_domain_mutation(disposition_fixture):
    client, _owner, project, asset, _authorization, scan, finding, _organization, _membership = disposition_fixture
    target = _other_finding(
        user=_owner,
        project=project,
        asset=asset,
        scan=scan,
        title='A3 API governed duplicate target',
    )
    request_id = uuid4()
    body = {
        'disposition': 'duplicate',
        'rationale': 'API proposal must remain immutable until independent approval.',
        'duplicate_of_id': str(target.id),
    }

    first = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/dispositions',
        json=body,
        headers={'X-Request-ID': str(request_id)},
    )
    assert first.status_code == 202, first.text
    payload = first.json()
    assert payload['action_id'] == 'finding.disposition.duplicate'
    assert payload['entity_type'] == 'finding'
    assert payload['entity_id'] == str(finding.id)
    assert payload['expected_version'] == finding.version
    assert payload['parameters'] == {
        'rationale': body['rationale'],
        'duplicate_of_id': str(target.id),
    }
    assert payload['replayed'] is False
    row = GovernedActionRequest.objects.get(pk=payload['request_id'])
    assert row.requested_by_id == _owner.id
    assert row.correlation_id == request_id
    assert not FindingDisposition.objects.filter(finding=finding).exists()

    replay = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/dispositions',
        json=body,
        headers={'X-Request-ID': str(request_id)},
    )
    assert replay.status_code == 202, replay.text
    assert replay.json()['request_id'] == payload['request_id']
    assert replay.json()['replayed'] is True
    assert GovernedActionRequest.objects.filter(
        action_id='finding.disposition.duplicate',
        entity_id=str(finding.id),
    ).count() == 1
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert not FindingDisposition.objects.filter(finding=finding).exists()
