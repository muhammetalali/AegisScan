from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import InvestigationCase, OrganizationMembership, TenantProject
from enterprise.soc_models import InvestigationCaseState
from fastapi_app.contracts.governed_operations import ActionMode
from fastapi_app.services.entity_capability_adapters import build_entity_capability_manifest
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.governed_responsibility_authority import grant_responsibility
from fastapi_app.services.test_campaign_objective_assurance import _setup as campaign_setup
from fastapi_app.services.test_finding_disposition import disposition_fixture, _risk_snapshot


pytestmark = pytest.mark.django_db(transaction=True)


def _owner(membership: OrganizationMembership) -> None:
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _grant_project(*, user, organization, membership, project, responsibility, key):
    return grant_responsibility(
        organization_id=str(organization.id),
        actor_id=str(user.id),
        membership_id=str(membership.id),
        responsibility=responsibility,
        scope_kind=GovernedResponsibilityAssignment.ScopeKind.PROJECT,
        project_id=str(project.id),
        reason=f'Scope guard reality assignment for {responsibility}.',
        idempotency_key=key,
    )


def _action(manifest, action_id: str):
    return next(item for item in manifest.capabilities if item.action_id == action_id)


def test_objective_evidence_on_unauthorized_intermediate_asset_does_not_enable_assessment(disposition_fixture):
    _client, user, project, source_asset, _authorization, scan, _finding, organization, membership = disposition_fixture
    _owner(membership)
    user, project, source_asset, _campaign, objective, path, source_evidence, _blast = campaign_setup(disposition_fixture)
    _grant_project(
        user=user, organization=organization, membership=membership, project=project,
        responsibility='campaign_assessor', key='scope-guard-campaign-assessor',
    )

    # Invalidate the only source-asset evidence without recomputing its digest,
    # then provide a valid Evidence record on a path asset that has no current
    # authorization. The capability adapter must not fall back to it.
    Evidence.objects.filter(pk=source_evidence.id).update(raw_output='tampered-after-seal')
    intermediate = Asset.objects.create(
        project=project,
        name='Unauthorized Intermediate',
        slug='unauthorized-intermediate-capability',
        type=Asset.Type.IP_ADDRESS,
        environment=source_asset.environment,
        criticality=source_asset.criticality,
        configuration={'host': 'unauthorized-intermediate'},
        owner=user,
    )
    path.steps = [str(source_asset.id), str(intermediate.id), str(source_asset.id)]
    path.save(update_fields=['steps', 'updated_at'])
    Evidence.objects.create(
        scan=scan,
        asset=intermediate,
        finding=None,
        source='agom-scope-guard',
        evidence_type='validation',
        raw_output='hash-valid evidence on unauthorized intermediate asset',
        collected_by=user,
    )

    manifest = build_entity_capability_manifest(
        project_id=str(project.id), user_id=str(user.id),
        entity_type='crown_jewel_objective', entity_id=str(objective.id),
    )
    action = _action(manifest, 'campaign.objective.assess')
    assert action.mode is ActionMode.BLOCKED
    assert action.reason_code == 'EVIDENCE_NOT_READY'
    assert 'evidence_asset_authorization' in action.missing_requirements


def test_soc_closure_ignores_cross_project_finding_disposition_even_if_case_m2m_is_malformed(disposition_fixture):
    _client, user, source_project, _asset, _authorization, _scan, finding, organization, membership = disposition_fixture
    _owner(membership)
    risk = _risk_snapshot(user=user, project=source_project, finding=finding, marker='scope-soc')
    govern_finding_disposition(
        finding_id=str(finding.id),
        disposition='accepted_risk',
        rationale='Cross-project scope guard disposition.',
        actor_id=str(user.id),
        risk_correlation_id=str(risk.id),
        review_at=timezone.now() + timedelta(days=30),
    )

    case_project = Project.objects.create(
        name='SOC Scope Guard Project',
        slug='soc-scope-guard-project',
        owner=user,
    )
    TenantProject.objects.create(organization=organization, project=case_project)
    case = InvestigationCase.objects.create(
        organization=organization,
        project=case_project,
        title='Cross-project malformed case',
        description='M2M intentionally contains a finding from another project.',
        status=InvestigationCase.Status.INVESTIGATING,
        owner=user,
    )
    case.findings.add(finding)
    InvestigationCaseState.objects.create(
        case=case,
        base_correlation_key='soc-scope-guard-cross-project',
        generation=1,
        version=1,
    )
    _grant_project(
        user=user, organization=organization, membership=membership, project=case_project,
        responsibility='soc_closure_approver', key='scope-guard-soc-closure',
    )

    manifest = build_entity_capability_manifest(
        project_id=str(case_project.id), user_id=str(user.id),
        entity_type='investigation_case', entity_id=str(case.id),
    )
    action = _action(manifest, 'investigation.close')
    assert action.mode is ActionMode.BLOCKED
    assert action.reason_code == 'EVIDENCE_NOT_READY'
    assert 'same_project_response_evidence' in action.missing_requirements
