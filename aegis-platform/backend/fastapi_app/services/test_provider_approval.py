from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.projects.models import Project
from enterprise.models import TenantProject
from enterprise.provider_approval_models import ProviderApprovalDecision
from fastapi_app.services.provider_approval import (
    evaluate_provider_admissibility,
    record_provider_decision,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)

CAPABILITY = 'burp.mcp.gateway'
SHA_A = 'a' * 64
SHA_B = 'b' * 64
SHA_C = 'c' * 64


def _manifest(marker: str = 'base', *, complete: bool = True) -> dict:
    data = {
        'license': 'enterprise-test',
        'maintenance': {'status': 'active'},
        'sbom': True,
        'supply_chain_integrity': True,
        'container_privileges': [],
        'network_permissions': ['authorized-target-only'],
        'determinism': True,
        'evidence_quality': True,
        'ci_reproducibility': True,
        'unmitigated_critical_cves': [],
        'mcp_endpoint': 'https://burp-provider.example.invalid/mcp',
        'mcp_tools': {'burp.site_map': 'burp_get_site_map'},
        'review_marker': marker,
    }
    if complete:
        data.update({
            'sbom_sha256': SHA_A,
            'provenance_sha256': SHA_B,
            'artifact_sha256': SHA_C,
            'signature_identity': 'https://github.com/example/provider/.github/workflows/release.yml@refs/tags/v1',
            'signature_verified': True,
        })
    return data


def _record(disposition_fixture, marker: str, *, status: str = 'approved', complete: bool = True, version: str = '2026.9'):
    _client, user, project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    return record_provider_decision(
        project_id=str(project.id),
        actor_id=str(user.id),
        provider_name='burp-suite-mcp',
        provider_version=version,
        capability=CAPABILITY,
        status=status,
        manifest=_manifest(marker, complete=complete),
        rationale=f'provider decision {marker}',
    )


def test_provider_decision_is_trusted_versioned_immutable_and_replay_safe(disposition_fixture):
    first = _record(disposition_fixture, 'trusted')
    second = _record(disposition_fixture, 'trusted')

    assert first.replayed is False
    assert second.replayed is True
    assert second.decision.id == first.decision.id
    decision = first.decision
    assert decision.decision_version == 1
    assert decision.status == ProviderApprovalDecision.Status.APPROVED
    assert decision.trust_state == ProviderApprovalDecision.TrustState.TRUSTED
    assert decision.predecessor_id is None
    assert decision.legacy_approval_id is not None
    assert len(decision.provider_identity_sha256) == 64
    assert len(decision.manifest_sha256) == 64
    assert len(decision.capability_manifest_sha256) == 64
    assert len(decision.supply_chain_sha256) == 64
    assert decision.supply_chain_evidence['signature_verified'] is True
    assert decision.capability_manifest['capabilities'] == [CAPABILITY]

    gate = evaluate_provider_admissibility(
        project_id=str(decision.project_id),
        provider_name=decision.provider_name,
        provider_version=decision.provider_version,
        capability=CAPABILITY,
        expected_legacy_approval_id=str(decision.legacy_approval_id),
        expected_decision_id=str(decision.id),
    )
    assert gate['allowed'] is True
    assert gate['decision_version'] == 1

    with pytest.raises(ValidationError):
        ProviderApprovalDecision.objects.filter(pk=decision.id).update(status='revoked')
    with pytest.raises(ValidationError):
        decision.delete()


def test_revocation_supersedes_prior_approval_and_old_pin_fails_closed(disposition_fixture):
    approved = _record(disposition_fixture, 'approved').decision
    revoked = _record(disposition_fixture, 'approved', status='revoked').decision

    assert revoked.decision_version == 2
    assert revoked.predecessor_id == approved.id
    assert revoked.status == ProviderApprovalDecision.Status.REVOKED
    assert revoked.trust_state == ProviderApprovalDecision.TrustState.UNTRUSTED

    gate = evaluate_provider_admissibility(
        project_id=str(approved.project_id),
        provider_name=approved.provider_name,
        provider_version=approved.provider_version,
        capability=CAPABILITY,
        expected_decision_id=str(approved.id),
    )
    assert gate['allowed'] is False
    assert any('status is revoked' in item for item in gate['failures'])
    assert any('decision pin is no longer current' in item for item in gate['failures'])


def test_provider_version_rotation_makes_old_version_non_current(disposition_fixture):
    old = _record(disposition_fixture, 'old', version='2026.9').decision
    new = _record(disposition_fixture, 'new', version='2026.10').decision

    assert new.decision_version == 2
    assert new.predecessor_id == old.id

    old_gate = evaluate_provider_admissibility(
        project_id=str(old.project_id),
        provider_name=old.provider_name,
        provider_version='2026.9',
        capability=CAPABILITY,
    )
    new_gate = evaluate_provider_admissibility(
        project_id=str(new.project_id),
        provider_name=new.provider_name,
        provider_version='2026.10',
        capability=CAPABILITY,
    )
    assert old_gate['allowed'] is False
    assert any('version is no longer' in item for item in old_gate['failures'])
    assert new_gate['allowed'] is True


def test_missing_supply_chain_proof_is_conditional_and_denied(disposition_fixture):
    decision = _record(disposition_fixture, 'incomplete', complete=False).decision
    assert decision.status == ProviderApprovalDecision.Status.APPROVED
    assert decision.trust_state == ProviderApprovalDecision.TrustState.CONDITIONAL

    gate = evaluate_provider_admissibility(
        project_id=str(decision.project_id),
        provider_name=decision.provider_name,
        provider_version=decision.provider_version,
        capability=CAPABILITY,
    )
    assert gate['allowed'] is False
    assert any('sbom_sha256' in item for item in gate['failures'])
    assert any('signature' in item for item in gate['failures'])


def test_provider_decisions_are_project_tenant_isolated(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, _finding, organization, _membership = disposition_fixture
    decision = _record(disposition_fixture, 'tenant').decision

    other = Project.objects.create(
        name='Provider Isolation Project',
        slug=f'provider-isolation-{str(project.id)[:8]}',
        owner=user,
    )
    TenantProject.objects.create(organization=organization, project=other)

    isolated = evaluate_provider_admissibility(
        project_id=str(other.id),
        provider_name=decision.provider_name,
        provider_version=decision.provider_version,
        capability=CAPABILITY,
    )
    assert isolated['allowed'] is False
    assert isolated['decision_id'] is None


def test_provider_approval_api_exposes_lineage_and_evaluation(disposition_fixture):
    client, _user, project, *_rest = disposition_fixture
    payload = {
        'provider_name': 'burp-suite-mcp',
        'provider_version': '2026.9',
        'capability': CAPABILITY,
        'status': 'approved',
        'manifest': _manifest('api'),
        'rationale': 'API governed approval',
    }
    response = client.post(
        f'/api/v1/provider-approvals/projects/{project.id}/decisions',
        json=payload,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body['decision_version'] == 1
    assert body['trust_state'] == 'trusted'
    assert body['legacy_approval_id']
    assert body['provider_identity_sha256']

    evaluation = client.post(
        f'/api/v1/provider-approvals/projects/{project.id}/evaluate',
        json={
            'provider_name': 'burp-suite-mcp',
            'provider_version': '2026.9',
            'capability': CAPABILITY,
            'expected_legacy_approval_id': body['legacy_approval_id'],
            'expected_decision_id': body['id'],
        },
    )
    assert evaluation.status_code == 200, evaluation.text
    assert evaluation.json()['allowed'] is True
