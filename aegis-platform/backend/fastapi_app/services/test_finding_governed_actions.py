from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest
from django.db import close_old_connections, connection

from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence, FindingConfirmation, FindingDisposition, ValidationRun
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.governed_action_models import GovernedActionExecution
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import OrganizationMembership
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.services.governed_action_executor import (
    GovernedActionBlocked,
    GovernedActionConflict,
    execute_governed_action,
)
from fastapi_app.services.governed_capability_manifest import build_governed_capability_manifest
from fastapi_app.services.governed_responsibility_authority import grant_responsibility
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def _grant(*, owner, project, organization, membership, responsibility: str, key: str):
    return grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(owner.id),
        membership_id=str(membership.id),
        responsibility=responsibility,
        scope_kind=GovernedResponsibilityAssignment.ScopeKind.PROJECT,
        project_id=str(project.id),
        reason=f'AGOM Finding Reality assignment for {responsibility}.',
        idempotency_key=key,
    )


def _actor(*, owner, project, organization, email: str, role: str, responsibility: str):
    user = User.objects.create_user(
        email=email,
        password='Strong-Test-Password-123!',
        first_name='AGOM',
        last_name='Actor',
    )
    project.members.add(user)
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=role,
        is_active=True,
    )
    _grant(
        owner=owner,
        project=project,
        organization=organization,
        membership=membership,
        responsibility=responsibility,
        key=f'{responsibility}-{user.id}',
    )
    return user, membership


def _validation(*, user, finding, authorization, finding_present: bool, remediation_state: str | None = None):
    result = {
        'tool': 'nmap',
        'target': 'aegis-disposition-target',
        'exit_code': 0,
        'finding_present': finding_present,
    }
    if remediation_state:
        result['remediation_state'] = remediation_state
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        authorization_decision=authorization,
        target_type='ip',
        target_value='aegis-disposition-target',
        scope='aegis-disposition-target',
        profile='quick',
        engines=['nmap'],
        authorized=True,
        status=ValidationRun.Status.COMPLETED,
        progress=100,
        current_phase='completed',
        result=result,
        completed_at=datetime.now(timezone.utc),
    )
    evidence = Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='nmap',
        evidence_type='validation_output',
        raw_output=f'<nmaprun finding_present="{str(finding_present).lower()}" />',
        metadata={
            'format': 'xml',
            'validation_run_id': str(validation.id),
            'validation_id': str(validation.id),
            'finding_present': finding_present,
            'authorization_decision_id': str(authorization.id),
        },
        collected_by=user,
    )
    validation.result = {**validation.result, 'evidence_id': str(evidence.id)}
    validation.save(update_fields=['result'])
    return validation, evidence


def _ownerize(membership):
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _use_api_actor(user):
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(user.id),
        'is_staff': False,
    }


def _confirmation_request(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    confirmer, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='agom-finding-confirmer@example.invalid',
        role=OrganizationMembership.Role.ANALYST,
        responsibility='finding_confirmer',
    )
    validation, evidence = _validation(
        user=confirmer,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    kwargs = {
        'action_id': 'finding.confirm',
        'project_id': str(project.id),
        'actor_id': str(confirmer.id),
        'entity_type': 'finding',
        'entity_id': str(finding.id),
        'expected_version': finding.version,
        'idempotency_key': 'finding-confirm-1',
        'parameters': {
            'validation_id': str(validation.id),
            'rationale': 'Independent governed confirmation evidence.',
        },
    }
    return owner, project, authorization, finding, organization, owner_membership, confirmer, validation, evidence, kwargs


def test_finding_manifest_exposes_durable_projection_version(disposition_fixture):
    _client, owner, project, _asset, _authorization, _scan, finding, _organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    manifest = build_governed_capability_manifest(
        project_id=str(project.id),
        user_id=str(owner.id),
        entity_type='finding',
        entity_id=str(finding.id),
    )
    assert manifest.projection.version == finding.version == 1


def test_finding_confirmation_creates_single_governed_envelope(disposition_fixture):
    _owner, _project, _authorization, finding, _organization, _owner_membership, _confirmer, validation, evidence, kwargs = _confirmation_request(disposition_fixture)
    result = execute_governed_action(**kwargs)
    assert result.replayed is False
    assert result.execution.action_id == 'finding.confirm'
    assert result.execution.before_projection['version'] == 1
    assert result.execution.after_projection['version'] == 2
    assert result.execution.result_payload['validation_id'] == str(validation.id)
    assert result.execution.result_payload['evidence_id'] == str(evidence.id)

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.CONFIRMED
    assert finding.version == 2
    assert FindingConfirmation.objects.filter(finding=finding, validation_run=validation).count() == 1
    assert GovernedActionExecution.objects.filter(action_id='finding.confirm', entity_id=str(finding.id)).count() == 1
    assert AuditLog.objects.filter(metadata__governed_action_id='finding.confirm', resource_id=str(finding.id)).count() == 1
    assert AuditLog.objects.filter(metadata__operation='finding_confirmation', resource_id=str(finding.id)).count() == 0


def test_finding_confirmation_exact_replay_has_no_second_domain_or_audit_write(disposition_fixture):
    _owner, _project, _authorization, finding, _organization, _owner_membership, _confirmer, validation, _evidence, kwargs = _confirmation_request(disposition_fixture)
    first = execute_governed_action(**kwargs)
    second = execute_governed_action(**kwargs)
    assert first.replayed is False
    assert second.replayed is True
    assert first.execution.id == second.execution.id
    finding.refresh_from_db()
    assert finding.version == 2
    assert FindingConfirmation.objects.filter(finding=finding, validation_run=validation).count() == 1
    assert GovernedActionExecution.objects.filter(action_id='finding.confirm', entity_id=str(finding.id)).count() == 1
    assert AuditLog.objects.filter(metadata__governed_action_id='finding.confirm', resource_id=str(finding.id)).count() == 1


def test_finding_confirmation_stale_version_fails_before_mutation(disposition_fixture):
    _owner, _project, _authorization, finding, _organization, _owner_membership, _confirmer, _validation_row, _evidence, kwargs = _confirmation_request(disposition_fixture)
    kwargs['expected_version'] = finding.version + 1
    with pytest.raises(GovernedActionConflict, match='Expected entity version'):
        execute_governed_action(**kwargs)
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.version == 1
    assert FindingConfirmation.objects.filter(finding=finding).count() == 0
    assert GovernedActionExecution.objects.filter(entity_id=str(finding.id)).count() == 0


def test_finding_confirmation_rejects_non_latest_validation_and_rolls_back(disposition_fixture):
    _owner, _project, authorization, finding, _organization, _owner_membership, confirmer, older, _evidence, kwargs = _confirmation_request(disposition_fixture)
    _validation(
        user=confirmer,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    kwargs['parameters'] = {
        'validation_id': str(older.id),
        'rationale': 'Attempt to execute an older validation after governance evaluated a newer one.',
    }
    with pytest.raises(ValueError, match='latest validation run evaluated by governance'):
        execute_governed_action(**kwargs)
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.version == 1
    assert FindingConfirmation.objects.filter(finding=finding).count() == 0
    assert GovernedActionExecution.objects.filter(entity_id=str(finding.id)).count() == 0


def test_finding_confirmation_audit_failure_rolls_back_domain_and_envelope(disposition_fixture, monkeypatch):
    _owner, _project, _authorization, finding, _organization, _owner_membership, _confirmer, _validation_row, _evidence, kwargs = _confirmation_request(disposition_fixture)

    def fail_audit(**_values):
        raise RuntimeError('forced finding audit append failure')

    monkeypatch.setattr('fastapi_app.services.governed_action_executor.append_audit', fail_audit)
    with pytest.raises(RuntimeError, match='forced finding audit append failure'):
        execute_governed_action(**kwargs)
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.version == 1
    assert FindingConfirmation.objects.filter(finding=finding).count() == 0
    assert GovernedActionExecution.objects.filter(entity_id=str(finding.id)).count() == 0


def test_finding_close_requires_independent_closer_and_creates_single_envelope(disposition_fixture):
    owner, project, authorization, finding, organization, _owner_membership, _confirmer, _validation_row, _evidence, confirm_kwargs = _confirmation_request(disposition_fixture)
    execute_governed_action(**confirm_kwargs)
    finding.refresh_from_db()

    verified, evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    closer, _closer_membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='agom-finding-closer@example.invalid',
        role=OrganizationMembership.Role.MANAGER,
        responsibility='closure_approver',
    )
    before = finding.version
    result = execute_governed_action(
        action_id='finding.close',
        project_id=str(project.id),
        actor_id=str(closer.id),
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=before,
        idempotency_key='finding-close-1',
        parameters={},
    )
    assert result.execution.before_projection['version'] == before
    assert result.execution.after_projection['version'] == before + 1
    assert result.execution.result_payload['validation_id'] == str(verified.id)
    assert result.execution.result_payload['evidence_id'] == str(evidence.id)

    finding.refresh_from_db()
    verified.refresh_from_db()
    assert finding.status == Vulnerability.Status.FIXED
    assert finding.fixed_by_id == closer.id
    assert finding.version == before + 1
    assert verified.result['remediation_state'] == 'closed'
    assert AuditLog.objects.filter(metadata__governed_action_id='finding.close', resource_id=str(finding.id)).count() == 1
    assert AuditLog.objects.filter(metadata__operation='finding_closure', resource_id=str(finding.id)).count() == 0


def test_finding_close_blocks_verifier_as_closer(disposition_fixture):
    owner, project, authorization, finding, organization, owner_membership, _confirmer, _validation_row, _evidence, confirm_kwargs = _confirmation_request(disposition_fixture)
    execute_governed_action(**confirm_kwargs)
    finding.refresh_from_db()
    _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    _grant(
        owner=owner,
        project=project,
        organization=organization,
        membership=owner_membership,
        responsibility='closure_approver',
        key=f'owner-closure-{finding.id}',
    )
    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='finding.close',
            project_id=str(project.id),
            actor_id=str(owner.id),
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=finding.version,
            idempotency_key='finding-close-sod',
            parameters={},
        )
    assert blocked.value.reason_code == 'SOD_VIOLATION'
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.CONFIRMED


def test_postgresql_concurrent_exact_confirmation_is_single_execution(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _owner, _project, _authorization, finding, _organization, _owner_membership, _confirmer, validation, _evidence, kwargs = _confirmation_request(disposition_fixture)
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return execute_governed_action(**kwargs)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(item.replayed for item in results) == [False, True]
    assert len({item.execution.id for item in results}) == 1
    finding.refresh_from_db()
    assert finding.version == 2
    assert FindingConfirmation.objects.filter(finding=finding, validation_run=validation).count() == 1
    assert GovernedActionExecution.objects.filter(action_id='finding.confirm', entity_id=str(finding.id)).count() == 1
    assert AuditLog.objects.filter(metadata__governed_action_id='finding.confirm', resource_id=str(finding.id)).count() == 1


def test_confirmation_compatibility_route_uses_governed_executor_and_replays(disposition_fixture):
    client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    confirmer, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='agom-route-confirmer@example.invalid',
        role=OrganizationMembership.Role.ANALYST,
        responsibility='finding_confirmer',
    )
    validation, _evidence = _validation(
        user=confirmer,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    _use_api_actor(confirmer)
    body = {
        'validation_id': str(validation.id),
        'verdict': 'confirmed',
        'rationale': 'Governed compatibility route confirmation.',
        'expected_version': finding.version,
        'idempotency_key': 'route-confirm-1',
    }
    first = client.post(f'/api/v1/vulnerabilities/{finding.id}/confirmations', json=body)
    assert first.status_code == 201, first.text
    assert first.json()['replayed'] is False
    second = client.post(f'/api/v1/vulnerabilities/{finding.id}/confirmations', json=body)
    assert second.status_code == 200, second.text
    assert second.json()['replayed'] is True
    assert second.json()['id'] == first.json()['id']
    assert GovernedActionExecution.objects.filter(action_id='finding.confirm', entity_id=str(finding.id)).count() == 1


def test_false_positive_compatibility_route_is_fail_closed(disposition_fixture):
    client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    confirmer, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='agom-false-positive@example.invalid',
        role=OrganizationMembership.Role.ANALYST,
        responsibility='finding_confirmer',
    )
    validation, _evidence = _validation(
        user=confirmer,
        finding=finding,
        authorization=authorization,
        finding_present=False,
    )
    _use_api_actor(confirmer)
    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json={
            'validation_id': str(validation.id),
            'verdict': 'false_positive',
            'rationale': 'False positive still requires its own governed action.',
            'expected_version': finding.version,
            'idempotency_key': 'route-false-positive-1',
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()['detail']['code'] == 'FALSE_POSITIVE_GOVERNED_ACTION_NOT_IMPLEMENTED'
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert FindingConfirmation.objects.filter(finding=finding).count() == 0


def test_disposition_compatibility_route_is_fail_closed(disposition_fixture):
    client, _owner, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/dispositions',
        json={
            'disposition': 'accepted_risk',
            'rationale': 'Risk acceptance must not bypass the governed action plane.',
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()['detail']['code'] == 'RISK_ACCEPTANCE_GOVERNED_ACTION_NOT_IMPLEMENTED'
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN
    assert FindingDisposition.objects.filter(finding=finding).count() == 0


def test_close_compatibility_route_uses_independent_governed_closure(disposition_fixture):
    client, owner, project, authorization, finding, organization, _owner_membership, _confirmer, _validation_row, _evidence, confirm_kwargs = _confirmation_request(disposition_fixture)
    execute_governed_action(**confirm_kwargs)
    finding.refresh_from_db()
    verified, _evidence = _validation(
        user=owner,
        finding=finding,
        authorization=authorization,
        finding_present=False,
        remediation_state='verified',
    )
    closer, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email='agom-route-closer@example.invalid',
        role=OrganizationMembership.Role.MANAGER,
        responsibility='closure_approver',
    )
    _use_api_actor(closer)
    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/close',
        json={
            'expected_version': finding.version,
            'idempotency_key': 'route-close-1',
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['closed'] is True
    assert payload['validation_id'] == str(verified.id)
    assert payload['version'] == finding.version + 1
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.FIXED
    assert finding.fixed_by_id == closer.id
