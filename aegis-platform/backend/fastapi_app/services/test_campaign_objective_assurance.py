from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.db import close_old_connections, connection
from django.core.exceptions import ValidationError

from django_project.evidence.models import Evidence
from enterprise.campaign_models import AdversaryCampaign, CampaignAuditEvent, CampaignObjectiveAssessment
from enterprise.models import AttackPath, BlastRadiusSnapshot
from fastapi_app.services.campaign_objective_assurance import (
    CampaignAssuranceError,
    add_objective,
    assess_objective,
    campaign_summary,
    complete_campaign,
    create_campaign,
    verify_campaign_chain,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture

pytestmark = pytest.mark.django_db(transaction=True)


def _setup(disposition_fixture):
    _client, user, project, asset, _authorization, scan, finding, organization, _membership = disposition_fixture
    campaign = create_campaign(project_id=str(project.id), user_id=str(user.id), name='Crown jewel validation campaign', source_asset_id=str(asset.id))
    objective, replayed = add_objective(
        campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id), expected_campaign_version=1,
        target_asset_id=str(asset.id), title='Reach crown jewel', objective_type='crown_jewel_access',
        success_criteria={'proof': 'validated-path-and-evidence'}, attack_techniques=['T1190'],
    )
    assert replayed is False
    path = AttackPath.objects.create(
        organization=organization, project=project,
        source_node={'asset_id': str(asset.id), 'name': asset.name},
        target_node={'asset_id': str(asset.id), 'name': asset.name},
        steps=[str(asset.id)], risk_score=91.0,
        evidence={'source': 'campaign-reality'}, status=AttackPath.Status.VALIDATED,
    )
    evidence = Evidence.objects.create(
        finding=finding, asset=asset, scan=scan, source='campaign-reality', evidence_type='validation',
        raw_output='authorized objective proof confirms crown jewel reachability', collected_by=user,
    )
    blast = BlastRadiusSnapshot.objects.create(
        organization=organization, project=project, attack_path=path, root_ref=str(asset.id),
        crown_jewel_refs=[str(asset.id)], impacted_nodes=[str(asset.id)], score=88.0,
        evidence_refs=[str(evidence.id)],
    )
    return user, project, asset, campaign, objective, path, evidence, blast


def test_reached_objective_requires_validated_path_and_produces_auditable_completion(disposition_fixture):
    user, project, _asset, campaign, objective, path, evidence, blast = _setup(disposition_fixture)
    result = assess_objective(
        objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id),
        expected_objective_version=1, attack_path_id=str(path.id), evidence_id=str(evidence.id),
        blast_radius_snapshot_id=str(blast.id), outcome='reached', reason_code='validated_path',
        explanation='Authorized evidence demonstrates objective reachability.',
    )
    assert result.replayed is False
    assert result.assessment.outcome == CampaignObjectiveAssessment.Outcome.REACHED
    assert result.assessment.path_risk_score == 91.0
    assert result.assessment.blast_radius_score == 88.0
    assert len(result.assessment.proof_sha256) == 64
    assert verify_campaign_chain(campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True

    campaign.refresh_from_db()
    completed = complete_campaign(campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id), expected_campaign_version=campaign.version)
    assert completed.status == AdversaryCampaign.Status.COMPLETED
    assert len(completed.completion_sha256) == 64
    summary = campaign_summary(campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id))
    assert summary['objectives'][0]['status'] == 'reached'
    assert summary['objectives'][0]['latest_assessment']['proof_sha256'] == result.assessment.proof_sha256


def test_reached_outcome_rejects_unvalidated_attack_path(disposition_fixture):
    user, project, _asset, campaign, objective, path, evidence, _blast = _setup(disposition_fixture)
    path.status = AttackPath.Status.DISCOVERED
    path.save(update_fields=['status', 'updated_at'])
    with pytest.raises(CampaignAssuranceError, match='validated AttackPath'):
        assess_objective(
            objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id),
            expected_objective_version=1, attack_path_id=str(path.id), evidence_id=str(evidence.id),
            outcome='reached', reason_code='not_validated',
        )
    assert CampaignObjectiveAssessment.objects.count() == 0


def test_blocked_outcome_accepts_discovered_path_and_preserves_reason(disposition_fixture):
    user, project, _asset, campaign, objective, path, evidence, _blast = _setup(disposition_fixture)
    path.status = AttackPath.Status.DISCOVERED
    path.save(update_fields=['status', 'updated_at'])
    result = assess_objective(
        objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id),
        expected_objective_version=1, attack_path_id=str(path.id), evidence_id=str(evidence.id),
        outcome='blocked', reason_code='control_prevented_progression', explanation='Preventive control stopped the objective path.',
    )
    assert result.assessment.outcome == 'blocked'
    assert result.assessment.reason_code == 'control_prevented_progression'


def test_assessment_and_audit_evidence_are_immutable(disposition_fixture):
    user, project, _asset, campaign, objective, path, evidence, _blast = _setup(disposition_fixture)
    result = assess_objective(
        objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id),
        expected_objective_version=1, attack_path_id=str(path.id), evidence_id=str(evidence.id),
        outcome='blocked', reason_code='prevented',
    )
    with pytest.raises(ValidationError):
        CampaignObjectiveAssessment.objects.filter(pk=result.assessment.pk).update(reason_code='tampered')
    with pytest.raises(ValidationError):
        result.assessment.delete()
    event = CampaignAuditEvent.objects.filter(campaign=campaign).first()
    with pytest.raises(ValidationError):
        CampaignAuditEvent.objects.filter(pk=event.pk).delete()


def test_postgresql_concurrent_exact_assessment_replay_is_idempotent(disposition_fixture):
    assert connection.vendor == 'postgresql'
    user, project, _asset, campaign, objective, path, evidence, blast = _setup(disposition_fixture)
    barrier = Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return assess_objective(
                objective_id=str(objective.id), campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id),
                expected_objective_version=1, attack_path_id=str(path.id), evidence_id=str(evidence.id),
                blast_radius_snapshot_id=str(blast.id), outcome='reached', reason_code='validated_path',
                explanation='Concurrent exact replay.',
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _n: worker(), range(2)))
    assert sorted(item.replayed for item in results) == [False, True]
    assert len({item.assessment.id for item in results}) == 1
    assert CampaignObjectiveAssessment.objects.filter(objective=objective).count() == 1
    assert verify_campaign_chain(campaign_id=str(campaign.id), project_id=str(project.id), user_id=str(user.id))['valid'] is True
