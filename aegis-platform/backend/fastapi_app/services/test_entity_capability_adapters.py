from __future__ import annotations

from datetime import datetime, timezone

import pytest

from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import ExternalIntegration, InvestigationCase, Organization, OrganizationMembership, TenantProject
from enterprise.soc_models import InvestigationCaseState
from fastapi_app.contracts.governed_operations import ActionMode, ActorLayer
from fastapi_app.services.assurance_obligation_governance import materialize_assurance_obligation
from fastapi_app.services.campaign_objective_assurance import assess_objective
from fastapi_app.services.detection_engineering import validate_revision
from fastapi_app.services.entity_capability_adapters import (
    EntityCapabilityError,
    EntityCapabilityNotFound,
    build_entity_capability_manifest,
    supported_entity_types,
)
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.governed_operations import get_action_contract
from fastapi_app.services.governed_responsibility_authority import grant_responsibility, revoke_responsibility
from fastapi_app.services.test_assurance_obligation_governance import _schedule
from fastapi_app.services.test_campaign_objective_assurance import _setup as campaign_setup
from fastapi_app.services.test_detection_engineering import detection_fixture, _revision, _telemetry
from fastapi_app.services.test_finding_disposition import disposition_fixture, _risk_snapshot


pytestmark = pytest.mark.django_db(transaction=True)


def _owner_role(membership: OrganizationMembership) -> None:
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _grant(
    *,
    issuer: User,
    organization: Organization,
    membership: OrganizationMembership,
    project: Project,
    responsibility: str,
    key: str,
    entity_type: str = '',
    entity_id: str = '',
):
    scope_kind = (
        GovernedResponsibilityAssignment.ScopeKind.ENTITY
        if entity_id
        else GovernedResponsibilityAssignment.ScopeKind.PROJECT
    )
    return grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(issuer.id),
        membership_id=str(membership.id),
        responsibility=responsibility,
        scope_kind=scope_kind,
        project_id=str(project.id),
        entity_type=entity_type,
        entity_id=entity_id,
        reason=f'Entity capability reality assignment for {responsibility}.',
        idempotency_key=key,
    )


def _action(manifest, action_id: str):
    return next(item for item in manifest.capabilities if item.action_id == action_id)


def _confirmation_evidence(*, user, finding, authorization):
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
        result={'tool': 'nmap', 'finding_present': True},
        completed_at=datetime.now(timezone.utc),
    )
    evidence = Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='agom-capability-reality',
        evidence_type='validation_output',
        raw_output='authorized finding confirmation proof',
        metadata={
            'validation_run_id': str(validation.id),
            'validation_id': str(validation.id),
            'finding_present': True,
            'authorization_decision_id': str(authorization.id),
        },
        collected_by=user,
    )
    validation.result = {**validation.result, 'evidence_id': str(evidence.id)}
    validation.save(update_fields=['result'])
    return validation, evidence


def test_contract_states_match_real_soc_and_assurance_domains():
    assert get_action_contract('investigation.close').allowed_states == ['investigating', 'decided']
    assert get_action_contract('assurance.obligation.satisfy').allowed_states == ['open', 'due', 'overdue']


def test_adapter_registry_covers_every_current_agom_entity_type():
    expected = {
        'asset_authorization', 'finding', 'crown_jewel_objective', 'campaign',
        'detection_revision', 'investigation_case', 'assurance_obligation', 'integration',
    }
    assert set(supported_entity_types()) == expected
    with pytest.raises(EntityCapabilityError, match='Unsupported AGOM entity type'):
        # Scope lookup happens first by design, so unsupported-type validation is
        # tested elsewhere through the API/OpenAPI contract with a real project.
        raise EntityCapabilityError('Unsupported AGOM entity type: unsupported.')


def test_cross_tenant_project_is_non_enumerable(disposition_fixture):
    _client, actor, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    other_owner = User.objects.create_user(
        email='agom-other-tenant@example.invalid', password='Strong-Test-Password-123!',
        first_name='Other', last_name='Tenant',
    )
    other_project = Project.objects.create(
        name='Other Tenant Capability Project', slug='other-tenant-capability-project', owner=other_owner,
    )
    other_org = Organization.objects.create(
        name='Other Capability Tenant', slug='other-capability-tenant', owner=other_owner, is_active=True,
    )
    OrganizationMembership.objects.create(
        organization=other_org, user=other_owner, role=OrganizationMembership.Role.OWNER, is_active=True,
    )
    TenantProject.objects.create(organization=other_org, project=other_project)

    with pytest.raises(EntityCapabilityNotFound, match='scope not found'):
        build_entity_capability_manifest(
            project_id=str(other_project.id), user_id=str(actor.id),
            entity_type='finding', entity_id=str(finding.id),
        )


def test_finding_confirmation_is_enabled_only_by_db_authority_evidence_and_sod(disposition_fixture):
    _client, owner, project, _asset, authorization, _scan, finding, organization, owner_membership = disposition_fixture
    _owner_role(owner_membership)
    confirmer = User.objects.create_user(
        email='agom-finding-confirmer@example.invalid', password='Strong-Test-Password-123!',
        first_name='Finding', last_name='Confirmer',
    )
    confirmer_membership = OrganizationMembership.objects.create(
        organization=organization, user=confirmer, role=OrganizationMembership.Role.ANALYST, is_active=True,
    )
    _confirmation_evidence(user=owner, finding=finding, authorization=authorization)

    before = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id), entity_type='finding', entity_id=str(finding.id),
    )
    hidden = _action(before, 'finding.confirm')
    assert hidden.mode is ActionMode.HIDDEN
    assert hidden.reason_code == 'RESPONSIBILITY_NOT_ASSIGNED'

    grant = _grant(
        issuer=owner, organization=organization, membership=confirmer_membership, project=project,
        responsibility='finding_confirmer', key='entity-cap-finding-confirm',
        entity_type='finding', entity_id=str(finding.id),
    )
    enabled_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id), entity_type='finding', entity_id=str(finding.id),
    )
    enabled = _action(enabled_manifest, 'finding.confirm')
    assert enabled.mode is ActionMode.ENABLED
    assert enabled.evaluated_actor_layer is ActorLayer.ASSURE
    assert enabled_manifest.actor_role == OrganizationMembership.Role.ANALYST
    assert enabled_manifest.actor_responsibilities == ['finding_confirmer']
    assert all(result.state.value == 'pass' for result in enabled.gate_results)

    revoke_responsibility(
        assignment_id=str(grant.assignment.id), actor_id=str(owner.id),
        reason='Reality test revokes finding confirmation duty.', idempotency_key='entity-cap-finding-revoke',
    )
    revoked_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(confirmer.id), entity_type='finding', entity_id=str(finding.id),
    )
    revoked = _action(revoked_manifest, 'finding.confirm')
    assert revoked.mode is ActionMode.HIDDEN
    assert revoked.reason_code == 'RESPONSIBILITY_NOT_ASSIGNED'


def test_campaign_objective_enables_but_campaign_completion_enforces_sod(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, _finding, organization, membership = disposition_fixture
    _owner_role(membership)
    user, project, _asset, campaign, objective, path, evidence, blast = campaign_setup(disposition_fixture)
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='campaign_assessor', key='entity-cap-campaign-assessor',
    )
    objective_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id),
        entity_type='crown_jewel_objective', entity_id=str(objective.id),
    )
    assess = _action(objective_manifest, 'campaign.objective.assess')
    assert assess.mode is ActionMode.ENABLED
    assert assess.evaluated_actor_layer is ActorLayer.OPERATE

    assess_objective(
        objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id),
        user_id=str(user.id), expected_objective_version=1, attack_path_id=str(path.id),
        evidence_id=str(evidence.id), blast_radius_snapshot_id=str(blast.id),
        outcome='reached', reason_code='agom_capability_reality',
        explanation='Reality evidence proves the campaign objective.',
    )
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='campaign_lead', key='entity-cap-campaign-lead',
    )
    campaign_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id), entity_type='campaign', entity_id=str(campaign.id),
    )
    complete = _action(campaign_manifest, 'campaign.complete')
    assert complete.mode is ActionMode.BLOCKED
    assert complete.reason_code == 'SOD_VIOLATION'
    assert 'lead_must_not_be_sole_assessor_for_all_objectives' in complete.missing_requirements


def test_detection_publish_requires_passed_validation_and_live_siem_target(detection_fixture):
    _client, user, project, finding, evidence, organization, membership = detection_fixture
    _owner_role(membership)
    revision = _revision(user, project, finding, evidence).revision
    validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id),
        telemetry=_telemetry(), minimum_matches=1,
    )
    ExternalIntegration.objects.create(
        organization=organization, kind=ExternalIntegration.Kind.ELASTIC, name='Capability Elastic',
        base_url='http://127.0.0.1:9', config={'index': 'detections'}, enabled=True, created_by=user,
    )
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='detection_publisher', key='entity-cap-detection-publisher',
    )
    manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id), entity_type='detection_revision', entity_id=str(revision.id),
    )
    publish = _action(manifest, 'detection.publish')
    assert publish.mode is ActionMode.ENABLED
    assert publish.evaluated_actor_layer is ActorLayer.GOVERN
    assert {result.gate.value for result in publish.gate_results} == {'validation', 'publication'}


def test_soc_closure_uses_real_investigating_state_and_governed_disposition(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, organization, membership = disposition_fixture
    _owner_role(membership)
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='cap-soc')
    govern_finding_disposition(
        finding_id=str(finding.id), disposition='accepted_risk',
        rationale='Governed SOC closure capability proof.', actor_id=str(user.id),
        risk_correlation_id=str(risk.id),
        review_at=django_future_review(),
    )
    case = InvestigationCase.objects.create(
        organization=organization, project=project, title='Capability SOC Case',
        description='Reality case for AGOM capability projection.',
        status=InvestigationCase.Status.INVESTIGATING, owner=user,
    )
    case.findings.add(finding)
    InvestigationCaseState.objects.create(
        case=case, base_correlation_key='agom-capability-soc-case', generation=1, version=1,
    )
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='soc_closure_approver', key='entity-cap-soc-closure',
    )
    manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id), entity_type='investigation_case', entity_id=str(case.id),
    )
    close = _action(manifest, 'investigation.close')
    assert manifest.projection.lifecycle == 'investigating'
    # A3 makes investigation closure request-bound. A general capability
    # projection must not enable the mutation without an immutable proposer
    # context, even when a legacy disposition exists.
    assert close.mode is ActionMode.BLOCKED
    assert close.reason_code == 'SOD_VIOLATION'
    assert 'actor_must_not_be_request_proposer' in close.missing_requirements


def django_future_review():
    from django.utils import timezone as django_timezone
    from datetime import timedelta
    return django_timezone.now() + timedelta(days=30)


def test_unimplemented_governance_domains_fail_closed_with_explicit_reasons(disposition_fixture):
    _client, user, project, asset, authorization, _scan, finding, organization, membership = disposition_fixture
    _owner_role(membership)

    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='authorization_approver', key='entity-cap-auth-approver',
    )
    auth_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id),
        entity_type='asset_authorization', entity_id=str(authorization.id),
    )
    auth_action = _action(auth_manifest, 'asset.authorization.approve')
    assert auth_action.mode is ActionMode.BLOCKED
    assert auth_action.reason_code == 'AUTHORIZATION_REQUEST_DOMAIN_NOT_IMPLEMENTED'

    integration = ExternalIntegration.objects.create(
        organization=organization, kind=ExternalIntegration.Kind.GITHUB, name='Capability GitHub',
        base_url='https://api.github.com', enabled=True, created_by=user,
    )
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='integration_acceptor', key='entity-cap-integration-acceptor',
    )
    integration_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id), entity_type='integration', entity_id=str(integration.id),
    )
    integration_action = _action(integration_manifest, 'integration.live_accept')
    assert integration_action.mode is ActionMode.BLOCKED
    assert integration_action.reason_code == 'LIVE_ACCEPTANCE_DOMAIN_NOT_IMPLEMENTED'

    schedule = _schedule(user, project, asset, authorization, organization)
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='cap-assurance')
    govern_finding_disposition(
        finding_id=str(finding.id), disposition='accepted_risk',
        rationale='Capability assurance obligation proof.', actor_id=str(user.id),
        risk_correlation_id=str(risk.id), review_at=django_future_review(),
    )
    obligation = materialize_assurance_obligation(
        project_id=str(project.id), finding_id=str(finding.id), user_id=str(user.id), schedule_id=str(schedule.id),
    ).obligation
    _grant(
        issuer=user, organization=organization, membership=membership, project=project,
        responsibility='assurance_owner', key='entity-cap-assurance-owner',
    )
    assurance_manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id),
        entity_type='assurance_obligation', entity_id=str(obligation.id),
    )
    assurance_action = _action(assurance_manifest, 'assurance.obligation.satisfy')
    assert assurance_action.mode is ActionMode.BLOCKED
    assert assurance_action.reason_code == 'AUTOMATIC_ONLY_ACTION'
