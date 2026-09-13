from __future__ import annotations

from datetime import datetime, timezone

import pytest

from django_project.evidence.models import Evidence, ValidationRun
from django_project.users.models import User
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import OrganizationMembership
from fastapi_app.contracts.governed_operations import ActionMode
from fastapi_app.services.entity_capability_adapters import build_entity_capability_manifest
from fastapi_app.services.governed_responsibility_authority import grant_responsibility
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def _grant_entity(*, issuer, organization, membership, project, finding, responsibility, key):
    return grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(issuer.id),
        membership_id=str(membership.id),
        responsibility=responsibility,
        scope_kind=GovernedResponsibilityAssignment.ScopeKind.ENTITY,
        project_id=str(project.id),
        entity_type='finding',
        entity_id=str(finding.id),
        reason=f'Freshness reality assignment for {responsibility}.',
        idempotency_key=key,
    )


def _action(manifest, action_id: str):
    return next(item for item in manifest.capabilities if item.action_id == action_id)


def _validation_with_evidence(*, user, finding, authorization, finding_present: bool, remediation_state: str = ''):
    result = {
        'tool': 'nmap',
        'finding_present': finding_present,
    }
    if remediation_state:
        result['remediation_state'] = remediation_state
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        authorization_decision=authorization,
        target_type='ip',
        target_value=authorization.target_snapshot,
        scope=authorization.target_snapshot,
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
        source='agom-freshness-reality',
        evidence_type='validation_output',
        raw_output=f'validation={validation.id};finding_present={finding_present};state={remediation_state}',
        metadata={
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


def test_newer_negative_validation_blocks_older_positive_confirmation_proof(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    confirmer = User.objects.create_user(
        email='agom-fresh-confirm@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Fresh',
        last_name='Confirmer',
    )
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=confirmer,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    _grant_entity(
        issuer=owner, organization=organization, membership=membership,
        project=project, finding=finding, responsibility='finding_confirmer',
        key='fresh-confirm-duty',
    )
    _validation_with_evidence(
        user=owner, finding=finding, authorization=authorization, finding_present=True,
    )
    before = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id),
        entity_type='finding', entity_id=str(finding.id),
    )
    assert _action(before, 'finding.confirm').mode is ActionMode.ENABLED

    _validation_with_evidence(
        user=owner, finding=finding, authorization=authorization, finding_present=False,
    )
    after = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id),
        entity_type='finding', entity_id=str(finding.id),
    )
    blocked = _action(after, 'finding.confirm')
    assert blocked.mode is ActionMode.BLOCKED
    assert blocked.reason_code == 'EVIDENCE_NOT_READY'
    assert 'latest_finding_present_validation' in blocked.missing_requirements


def test_finding_present_false_never_advertises_confirm_action(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    confirmer = User.objects.create_user(
        email='agom-negative-confirm@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Negative',
        last_name='Confirmer',
    )
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=confirmer,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    _grant_entity(
        issuer=owner, organization=organization, membership=membership,
        project=project, finding=finding, responsibility='finding_confirmer',
        key='negative-confirm-duty',
    )
    _validation_with_evidence(
        user=owner, finding=finding, authorization=authorization, finding_present=False,
    )
    manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id),
        entity_type='finding', entity_id=str(finding.id),
    )
    action = _action(manifest, 'finding.confirm')
    assert action.mode is ActionMode.BLOCKED
    assert action.reason_code == 'EVIDENCE_NOT_READY'


def test_newer_validation_invalidates_older_verified_remediation_capability(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    owner_membership.role = OrganizationMembership.Role.OWNER
    owner_membership.save(update_fields=['role'])
    closer = User.objects.create_user(
        email='agom-fresh-closer@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Fresh',
        last_name='Closer',
    )
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=closer,
        role=OrganizationMembership.Role.MANAGER,
        is_active=True,
    )
    _grant_entity(
        issuer=owner, organization=organization, membership=membership,
        project=project, finding=finding, responsibility='closure_approver',
        key='fresh-closure-duty',
    )
    _validation_with_evidence(
        user=owner, finding=finding, authorization=authorization,
        finding_present=False, remediation_state='verified',
    )
    before = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(closer.id),
        entity_type='finding', entity_id=str(finding.id),
    )
    assert _action(before, 'finding.close').mode is ActionMode.ENABLED

    _validation_with_evidence(
        user=owner, finding=finding, authorization=authorization, finding_present=True,
    )
    after = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(closer.id),
        entity_type='finding', entity_id=str(finding.id),
    )
    blocked = _action(after, 'finding.close')
    assert blocked.mode is ActionMode.BLOCKED
    assert blocked.reason_code == 'STATE_PRECONDITION_UNMET'
    assert after.projection.lifecycle == 'pending_confirmation'
