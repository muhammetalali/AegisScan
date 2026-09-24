from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from enterprise.models import WSTGMethodologyAttestation
from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.models import Organization, OrganizationMembership, TenantProject
from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.wstg_completion_attestation import WSTGAttestationError, create_wstg_methodology_attestation
from fastapi_app.services.wstg_observation_lineage import attach_wstg_evidence_metadata
from fastapi_app.services.wstg_reporting import build_wstg_project_coverage


@pytest.mark.django_db
def test_gap_native_small_can_be_completed_only_through_qualified_governed_attestation():
    producer = User.objects.create_user(
        email='wstg-producer@example.invalid',
        password='Strong-Test-Password-123!',
    )
    analyst = User.objects.create_user(
        email='wstg-analyst@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Completion Attestation',
        slug='wstg-completion-attestation',
        owner=producer,
    )
    project.members.add(analyst)
    organization = Organization.objects.create(
        name='WSTG Completion Organization',
        slug='wstg-completion-organization',
        owner=producer,
    )
    TenantProject.objects.create(organization=organization, project=project)
    OrganizationMembership.objects.create(
        organization=organization,
        user=producer,
        role=OrganizationMembership.Role.OWNER,
    )
    OrganizationMembership.objects.create(
        organization=organization,
        user=analyst,
        role=OrganizationMembership.Role.ANALYST,
    )
    asset = Asset.objects.create(
        project=project,
        owner=producer,
        name='WSTG completion target',
        slug='wstg-completion-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'ip': '127.0.0.1'},
    )

    capability_id = 'web.duplicate-parameter-semantics'
    capability = get_capability(capability_id)
    evidence = Evidence.objects.create(
        asset=asset,
        source=capability.tool,
        evidence_type='scanner_output',
        raw_output='{"schema":"aegis.test.wstg-gap-observation.v1"}',
        metadata=attach_wstg_evidence_metadata(
            {'target': 'http://127.0.0.1/?a=1&a=2'},
            capability_id,
        ),
        collected_by=producer,
    )

    before = build_wstg_project_coverage(project)
    before_row = {item['wstg_id']: item for item in before['tests']}['WSTG-v42-INPV-04']
    assert before_row['state'] == 'observed'
    assert before_row['completion_claim_supported'] is True
    assert before_row['completion_claim_allowed'] is False
    assert before_row['methodology_completed'] is False

    attestation = create_wstg_methodology_attestation(
        project_id=str(project.id),
        actor_id=str(analyst.id),
        wstg_id='WSTG-v42-INPV-04',
        evidence_ids=[str(evidence.id)],
        rationale='Reviewed the trusted duplicate-parameter observation and methodology evidence.',
        decision='completed',
    )
    assert attestation['decision'] == 'completed'
    assert attestation['classification'] == 'GAP_NATIVE_SMALL'
    assert attestation['completion_mode'] == 'evidence_plus_governed_attestation'
    assert WSTGMethodologyAttestation.objects.count() == 1

    after = build_wstg_project_coverage(project)
    after_row = {item['wstg_id']: item for item in after['tests']}['WSTG-v42-INPV-04']
    assert after_row['completion_claim_allowed'] is True
    assert after_row['methodology_completed'] is True
    assert after_row['completion_attestation_id'] == attestation['id']
    assert after['summary']['methodology_completed_tests'] >= 1
    assert after['completion_claim_allowed'] is False
    assert 'passed' not in {item['state'] for item in after['tests']}
    assert 'failed' not in {item['state'] for item in after['tests']}

    record = WSTGMethodologyAttestation.objects.get(pk=attestation['id'])
    record.rationale = 'attempted mutation must fail'
    with pytest.raises(ValidationError):
        record.save()
    with pytest.raises(ValidationError):
        WSTGMethodologyAttestation.objects.filter(pk=record.pk).update(rationale='forbidden')
    with pytest.raises(ValidationError):
        record.delete()


@pytest.mark.django_db
def test_conditional_wstg_row_can_complete_when_applicable_with_trusted_lineage():
    producer = User.objects.create_user(
        email='wstg-conditional-producer@example.invalid',
        password='Strong-Test-Password-123!',
    )
    analyst = User.objects.create_user(
        email='wstg-conditional-analyst@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Conditional Completion',
        slug='wstg-conditional-completion',
        owner=producer,
    )
    project.members.add(analyst)
    organization = Organization.objects.create(
        name='WSTG Conditional Organization',
        slug='wstg-conditional-organization',
        owner=producer,
    )
    TenantProject.objects.create(organization=organization, project=project)
    OrganizationMembership.objects.create(
        organization=organization,
        user=producer,
        role=OrganizationMembership.Role.OWNER,
    )
    OrganizationMembership.objects.create(
        organization=organization,
        user=analyst,
        role=OrganizationMembership.Role.ANALYST,
    )
    asset = Asset.objects.create(
        project=project,
        owner=producer,
        name='Conditional browser target',
        slug='conditional-browser-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://example.test'},
    )
    capability_id = 'browser.spa-discovery'
    capability = get_capability(capability_id)
    evidence = Evidence.objects.create(
        asset=asset,
        source=capability.tool,
        evidence_type='scanner_output',
        raw_output='{"schema":"aegis.test.browser-observation.v1"}',
        metadata=attach_wstg_evidence_metadata(
            {'target': 'https://example.test'},
            capability_id,
        ),
        collected_by=producer,
    )

    attestation = create_wstg_methodology_attestation(
        project_id=str(project.id),
        actor_id=str(analyst.id),
        wstg_id='WSTG-v42-CLNT-08',
        evidence_ids=[str(evidence.id)],
        rationale='Flash applicability was reviewed and the trusted browser methodology evidence was completed.',
        decision='completed',
    )
    assert attestation['decision'] == 'completed'

    coverage = build_wstg_project_coverage(project)
    row = {item['wstg_id']: item for item in coverage['tests']}['WSTG-v42-CLNT-08']
    assert row['state'] == 'observed'
    assert row['completion_claim_allowed'] is True
    assert row['methodology_completed'] is True


@pytest.mark.django_db
def test_wstg_completion_attestation_enforces_separation_of_duties():
    analyst = User.objects.create_user(
        email='wstg-self-attest@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Separation of Duties',
        slug='wstg-separation-of-duties',
        owner=analyst,
    )
    organization = Organization.objects.create(
        name='WSTG Separation Organization',
        slug='wstg-separation-organization',
        owner=analyst,
    )
    TenantProject.objects.create(organization=organization, project=project)
    OrganizationMembership.objects.create(
        organization=organization,
        user=analyst,
        role=OrganizationMembership.Role.OWNER,
    )
    asset = Asset.objects.create(
        project=project,
        owner=analyst,
        name='Self-attested target',
        slug='self-attested-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://example.test'},
    )
    capability_id = 'web.duplicate-parameter-semantics'
    capability = get_capability(capability_id)
    evidence = Evidence.objects.create(
        asset=asset,
        source=capability.tool,
        evidence_type='scanner_output',
        raw_output='{"schema":"aegis.test.self-attested.v1"}',
        metadata=attach_wstg_evidence_metadata(
            {'target': 'https://example.test/?a=1&a=2'},
            capability_id,
        ),
        collected_by=analyst,
    )

    with pytest.raises(WSTGAttestationError, match='separation of duties'):
        create_wstg_methodology_attestation(
            project_id=str(project.id),
            actor_id=str(analyst.id),
            wstg_id='WSTG-v42-INPV-04',
            evidence_ids=[str(evidence.id)],
            rationale='This self-produced evidence must not satisfy governed methodology completion.',
            decision='completed',
        )
