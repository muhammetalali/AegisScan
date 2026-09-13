from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection

from django_project.audit.models import AuditLog
from django_project.audit.services import verify_audit_chain
from django_project.users.models import User
from enterprise.campaign_models import AdversaryCampaign, CampaignObjectiveAssessment
from enterprise.governed_action_models import GovernedActionExecution
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import OrganizationMembership
from fastapi_app.services.governed_action_executor import (
    GovernedActionBlocked,
    GovernedActionConflict,
    execute_governed_action,
)
from fastapi_app.services.governed_responsibility_authority import grant_responsibility
from fastapi_app.services.test_campaign_objective_assurance import _setup
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
        reason=f'AGOM Reality assignment for {responsibility}.',
        idempotency_key=key,
    )


def _assessment_request(disposition_fixture, *, grant=True):
    user, project, _asset, campaign, objective, path, evidence, blast = _setup(disposition_fixture)
    organization = campaign.organization
    membership = OrganizationMembership.objects.get(organization=organization, user=user)
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])
    if grant:
        _grant(
            owner=user,
            project=project,
            organization=organization,
            membership=membership,
            responsibility='campaign_assessor',
            key=f'assessor-{objective.id}',
        )
    kwargs = {
        'action_id': 'campaign.objective.assess',
        'project_id': str(project.id),
        'actor_id': str(user.id),
        'entity_type': 'crown_jewel_objective',
        'entity_id': str(objective.id),
        'expected_version': objective.version,
        'idempotency_key': 'objective-assess-1',
        'parameters': {
            'campaign_id': str(campaign.id),
            'attack_path_id': str(path.id),
            'evidence_id': str(evidence.id),
            'blast_radius_snapshot_id': str(blast.id),
            'outcome': 'reached',
            'reason_code': 'validated_path',
            'explanation': 'Governed executor Reality proof.',
        },
    }
    return user, project, organization, membership, campaign, objective, kwargs


def test_objective_assessment_creates_atomic_immutable_envelope(disposition_fixture):
    _user, _project, _organization, _membership, _campaign, objective, kwargs = _assessment_request(disposition_fixture)
    result = execute_governed_action(**kwargs)
    assert result.replayed is False
    execution = result.execution
    assert execution.action_id == 'campaign.objective.assess'
    assert execution.entity_id == str(objective.id)
    assert execution.before_projection['version'] == 1
    assert execution.after_projection['version'] == 2
    assert execution.result_payload['outcome'] == 'reached'
    assert len(execution.policy_fingerprint) == 64
    assert len(execution.execution_fingerprint) == 64
    assert execution.audit_log.metadata['governed_action_id'] == 'campaign.objective.assess'
    assert execution.audit_log.metadata['request_fingerprint'] == execution.request_fingerprint
    assert execution.audit_log.entry_hash
    assert verify_audit_chain()[0] is True

    with pytest.raises(ValidationError):
        GovernedActionExecution.objects.filter(pk=execution.id).update(result_payload={'tampered': True})
    with pytest.raises(ValidationError):
        execution.delete()


def test_exact_idempotency_replays_without_second_domain_or_audit_write(disposition_fixture):
    _user, _project, _organization, _membership, _campaign, objective, kwargs = _assessment_request(disposition_fixture)
    first = execute_governed_action(**kwargs)
    second = execute_governed_action(**kwargs)
    assert first.replayed is False
    assert second.replayed is True
    assert first.execution.id == second.execution.id
    assert GovernedActionExecution.objects.filter(entity_id=str(objective.id)).count() == 1
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 1
    assert AuditLog.objects.filter(metadata__governed_action_id='campaign.objective.assess').count() == 1


def test_idempotency_key_conflict_is_rejected(disposition_fixture):
    _user, _project, _organization, _membership, _campaign, _objective, kwargs = _assessment_request(disposition_fixture)
    execute_governed_action(**kwargs)
    conflicting = dict(kwargs)
    conflicting['parameters'] = {**kwargs['parameters'], 'reason_code': 'different_intent'}
    with pytest.raises(GovernedActionConflict, match='Idempotency key'):
        execute_governed_action(**conflicting)


def test_missing_governed_responsibility_is_hidden_and_not_executed(disposition_fixture):
    _user, _project, _organization, _membership, _campaign, objective, kwargs = _assessment_request(disposition_fixture, grant=False)
    with pytest.raises(PermissionError, match='not available'):
        execute_governed_action(**kwargs)
    assert GovernedActionExecution.objects.filter(entity_id=str(objective.id)).count() == 0
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 0


def test_stale_expected_version_fails_before_domain_mutation(disposition_fixture):
    _user, _project, _organization, _membership, _campaign, objective, kwargs = _assessment_request(disposition_fixture)
    kwargs['expected_version'] = objective.version + 1
    with pytest.raises(GovernedActionConflict, match='Expected entity version'):
        execute_governed_action(**kwargs)
    assert GovernedActionExecution.objects.filter(entity_id=str(objective.id)).count() == 0
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 0


def test_failure_after_domain_mutation_rolls_back_domain_audit_and_envelope(disposition_fixture, monkeypatch):
    _user, _project, _organization, _membership, campaign, objective, kwargs = _assessment_request(disposition_fixture)

    def fail_audit(**_values):
        raise RuntimeError('forced audit append failure')

    monkeypatch.setattr('fastapi_app.services.governed_action_executor.append_audit', fail_audit)
    with pytest.raises(RuntimeError, match='forced audit append failure'):
        execute_governed_action(**kwargs)

    objective.refresh_from_db()
    campaign.refresh_from_db()
    assert objective.version == 1
    assert objective.status == 'pending'
    assert campaign.version == 2
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 0
    assert GovernedActionExecution.objects.filter(entity_id=str(objective.id)).count() == 0


def test_campaign_completion_requires_independent_lead_and_creates_envelope(disposition_fixture):
    owner, project, organization, owner_membership, campaign, _objective, assess_kwargs = _assessment_request(disposition_fixture)
    execute_governed_action(**assess_kwargs)
    campaign.refresh_from_db()

    _grant(
        owner=owner,
        project=project,
        organization=organization,
        membership=owner_membership,
        responsibility='campaign_lead',
        key=f'owner-lead-{campaign.id}',
    )
    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='campaign.complete',
            project_id=str(project.id),
            actor_id=str(owner.id),
            entity_type='campaign',
            entity_id=str(campaign.id),
            expected_version=campaign.version,
            idempotency_key='owner-complete-blocked',
            parameters={},
        )
    assert blocked.value.reason_code == 'SOD_VIOLATION'

    lead = User.objects.create_user(
        email='agom-campaign-lead@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Campaign',
        last_name='Lead',
    )
    project.members.add(lead)
    lead_membership = OrganizationMembership.objects.create(
        organization=organization,
        user=lead,
        role=OrganizationMembership.Role.MANAGER,
        is_active=True,
    )
    _grant(
        owner=owner,
        project=project,
        organization=organization,
        membership=lead_membership,
        responsibility='campaign_lead',
        key=f'independent-lead-{campaign.id}',
    )
    result = execute_governed_action(
        action_id='campaign.complete',
        project_id=str(project.id),
        actor_id=str(lead.id),
        entity_type='campaign',
        entity_id=str(campaign.id),
        expected_version=campaign.version,
        idempotency_key='independent-complete',
        parameters={},
    )
    assert result.execution.result_payload['status'] == AdversaryCampaign.Status.COMPLETED
    assert result.execution.after_projection['lifecycle'] == AdversaryCampaign.Status.COMPLETED
    assert GovernedActionExecution.objects.filter(action_id='campaign.complete').count() == 1


def test_postgresql_concurrent_exact_action_is_single_execution(disposition_fixture):
    assert connection.vendor == 'postgresql'
    _user, _project, _organization, _membership, _campaign, objective, kwargs = _assessment_request(disposition_fixture)
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
    assert GovernedActionExecution.objects.filter(entity_id=str(objective.id)).count() == 1
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 1
    assert AuditLog.objects.filter(metadata__governed_action_id='campaign.objective.assess').count() == 1
