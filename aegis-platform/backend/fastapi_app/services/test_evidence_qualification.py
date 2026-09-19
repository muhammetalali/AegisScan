from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from enterprise.governed_action_models import EvidenceQualificationEvaluation
from enterprise.models import Organization, TenantProject
from fastapi_app.services.evidence_qualification import (
    EvidenceQualificationPolicy,
    qualify_evidence,
)
from fastapi_app.services.governed_action_executor import execute_governed_action
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_finding_governed_actions import _confirmation_request


pytestmark = pytest.mark.django_db(transaction=True)


def _policy(**overrides) -> EvidenceQualificationPolicy:
    values = {
        'policy_version': 'test-evidence-qualification.v1',
        'min_count': 1,
        'evidence_types': ('validation_output',),
        'require_subject': True,
        'require_target': True,
        'require_authorization': True,
        'require_execution': True,
        'require_producer': True,
    }
    values.update(overrides)
    return EvidenceQualificationPolicy(**values)


def _context(disposition_fixture):
    (
        _owner,
        project,
        authorization,
        finding,
        organization,
        _owner_membership,
        confirmer,
        validation,
        evidence,
        kwargs,
    ) = _confirmation_request(disposition_fixture)
    return {
        'project': project,
        'authorization': authorization,
        'finding': finding,
        'organization': organization,
        'actor': confirmer,
        'validation': validation,
        'evidence': evidence,
        'kwargs': kwargs,
    }


def _qualify(ctx, *, evidence_ids=None, target=None, execution_ref=None, subject_id=None, policy=None, evaluated_at=None):
    return qualify_evidence(
        project_id=str(ctx['project'].id),
        organization_id=str(ctx['organization'].id),
        evidence_ids=evidence_ids or [str(ctx['evidence'].id)],
        subject_type='finding',
        subject_id=subject_id or str(ctx['finding'].id),
        target=target if target is not None else ctx['validation'].target_value,
        authorization_ref=str(ctx['authorization'].id),
        execution_ref=execution_ref if execution_ref is not None else str(ctx['validation'].id),
        requested_by_id=str(ctx['actor'].id),
        policy=policy or _policy(),
        evaluated_at=evaluated_at,
    )


def test_valid_evidence_is_qualified_persisted_and_reproducible(disposition_fixture):
    ctx = _context(disposition_fixture)
    as_of = timezone.now()
    first = _qualify(ctx, evaluated_at=as_of)
    second = _qualify(ctx, evaluated_at=as_of)

    assert first.qualified is True
    assert first.evaluation.decision == EvidenceQualificationEvaluation.Decision.QUALIFIED
    assert len(first.evaluation.evidence_set_hash) == 64
    assert len(first.evaluation.evaluation_fingerprint) == 64
    assert first.evaluation.policy_version == 'test-evidence-qualification.v1'
    assert first.replayed is False
    assert second.replayed is True
    assert second.evaluation.id == first.evaluation.id

    with pytest.raises(ValidationError):
        EvidenceQualificationEvaluation.objects.filter(pk=first.evaluation.id).update(decision='stale')
    with pytest.raises(ValidationError):
        first.evaluation.delete()


def test_cross_tenant_evidence_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    other_project = Project.objects.create(name='Other tenant project', slug='other-tenant-project', owner=ctx['actor'])
    other_org = Organization.objects.create(name='Other tenant', slug='other-evidence-tenant', owner=ctx['actor'])
    TenantProject.objects.create(organization=other_org, project=other_project)
    other_asset = Asset.objects.create(
        project=other_project,
        name='Other tenant target',
        slug='other-tenant-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': 'other-tenant-target'},
        owner=ctx['actor'],
    )
    Evidence.objects.filter(pk=ctx['evidence'].id).update(asset=other_asset)

    result = _qualify(ctx)
    assert result.qualified is False
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.WRONG_TENANT


def test_same_tenant_wrong_project_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    other_project = Project.objects.create(name='Sibling project', slug='sibling-evidence-project', owner=ctx['actor'])
    TenantProject.objects.create(organization=ctx['organization'], project=other_project)
    other_asset = Asset.objects.create(
        project=other_project,
        name='Sibling target',
        slug='sibling-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': 'sibling-target'},
        owner=ctx['actor'],
    )
    Evidence.objects.filter(pk=ctx['evidence'].id).update(asset=other_asset)

    result = _qualify(ctx)
    assert result.qualified is False
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.WRONG_PROJECT


@pytest.mark.parametrize(
    ('mutation', 'expected'),
    [
        ('revoked', EvidenceQualificationEvaluation.Decision.REVOKED),
        ('superseded', EvidenceQualificationEvaluation.Decision.SUPERSEDED),
        ('contradicted', EvidenceQualificationEvaluation.Decision.CONTRADICTED),
    ],
)
def test_evidence_lifecycle_state_is_fail_closed(disposition_fixture, mutation, expected):
    ctx = _context(disposition_fixture)
    metadata = dict(ctx['evidence'].metadata)
    if mutation == 'revoked':
        metadata['revoked_at'] = timezone.now().isoformat()
    elif mutation == 'superseded':
        metadata['superseded_by'] = str(uuid4())
    else:
        metadata['contradiction_state'] = 'contradicted'
    Evidence.objects.filter(pk=ctx['evidence'].id).update(metadata=metadata)

    result = _qualify(ctx)
    assert result.qualified is False
    assert result.evaluation.decision == expected


def test_stale_evidence_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    as_of = timezone.now()
    Evidence.objects.filter(pk=ctx['evidence'].id).update(collected_at=as_of - timedelta(hours=2))
    result = _qualify(ctx, policy=_policy(max_age_seconds=60), evaluated_at=as_of)
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.STALE


def test_expired_current_authorization_is_not_authorized(disposition_fixture):
    ctx = _context(disposition_fixture)
    expired = AssetAuthorization.objects.create(
        asset=ctx['finding'].asset,
        actor=ctx['actor'],
        authorized=True,
        target_snapshot=ctx['validation'].target_value,
        reason='Expired evidence qualification test decision',
        expires_at=timezone.now() - timedelta(seconds=1),
    )
    metadata = dict(ctx['evidence'].metadata)
    metadata['authorization_decision_id'] = str(expired.id)
    Evidence.objects.filter(pk=ctx['evidence'].id).update(metadata=metadata)
    ctx['authorization'] = expired

    result = _qualify(ctx, evaluated_at=timezone.now())
    assert result.qualified is False
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED


def test_wrong_target_execution_and_subject_are_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    wrong_target = _qualify(ctx, target='different-authorized-target')
    assert wrong_target.evaluation.decision == EvidenceQualificationEvaluation.Decision.WRONG_TARGET

    wrong_execution = _qualify(ctx, execution_ref=str(uuid4()))
    assert wrong_execution.evaluation.decision == EvidenceQualificationEvaluation.Decision.WRONG_EXECUTION

    wrong_subject = _qualify(ctx, subject_id=str(uuid4()))
    assert wrong_subject.evaluation.decision == EvidenceQualificationEvaluation.Decision.WRONG_SUBJECT


def test_integrity_mismatch_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    Evidence.objects.filter(pk=ctx['evidence'].id).update(raw_output='tampered-without-rehash')
    result = _qualify(ctx)
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.INTEGRITY_MISMATCH


def test_missing_producer_provenance_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    Evidence.objects.filter(pk=ctx['evidence'].id).update(collected_by=None)
    result = _qualify(ctx)
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE


def test_duplicate_evidence_reference_is_rejected_as_replay(disposition_fixture):
    ctx = _context(disposition_fixture)
    result = _qualify(ctx, evidence_ids=[str(ctx['evidence'].id), str(ctx['evidence'].id)])
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.REPLAYED_EVIDENCE


def test_incomplete_evidence_set_is_rejected(disposition_fixture):
    ctx = _context(disposition_fixture)
    result = _qualify(ctx, policy=_policy(min_count=2))
    assert result.evaluation.decision == EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE


def test_finding_confirm_governed_action_embeds_authoritative_qualification(disposition_fixture):
    ctx = _context(disposition_fixture)
    result = execute_governed_action(**ctx['kwargs'])
    qualification = result.execution.result_payload['evidence_qualification']

    assert qualification['decision'] == EvidenceQualificationEvaluation.Decision.QUALIFIED
    assert qualification['qualified'] is True
    assert qualification['policy_version'] == 'finding-confirmation-evidence.v1'
    assert len(qualification['evidence_set_hash']) == 64
    assert len(qualification['evaluation_fingerprint']) == 64
    evaluation = EvidenceQualificationEvaluation.objects.get(pk=qualification['evaluation_id'])
    assert evaluation.subject_type == 'finding'
    assert evaluation.subject_id == str(ctx['finding'].id)
    assert evaluation.execution_ref == str(ctx['validation'].id)
    assert evaluation.authorization_ref == str(ctx['authorization'].id)
    assert str(ctx['evidence'].id) in evaluation.requested_evidence_ids


def test_finding_confirm_preserves_qualification_when_downstream_domain_write_fails(disposition_fixture, monkeypatch):
    ctx = _context(disposition_fixture)

    def fail_after_qualification(**_kwargs):
        raise RuntimeError('forced domain failure after qualification')

    monkeypatch.setattr('fastapi_app.services.governed_action_executor.confirm_finding', fail_after_qualification)
    with pytest.raises(RuntimeError, match='forced domain failure after qualification'):
        execute_governed_action(**ctx['kwargs'])

    evaluation = EvidenceQualificationEvaluation.objects.get()
    assert evaluation.qualified is True
    ctx['finding'].refresh_from_db()
    assert ctx['finding'].status == 'open'


def test_finding_confirm_blocks_revoked_evidence_and_persists_decision(disposition_fixture):
    ctx = _context(disposition_fixture)
    metadata = dict(ctx['evidence'].metadata)
    metadata['revoked_at'] = timezone.now().isoformat()
    Evidence.objects.filter(pk=ctx['evidence'].id).update(metadata=metadata)

    from fastapi_app.services.governed_action_executor import GovernedActionBlocked

    with pytest.raises(GovernedActionBlocked, match='Evidence qualification rejected'):
        execute_governed_action(**ctx['kwargs'])

    evaluation = EvidenceQualificationEvaluation.objects.get()
    assert evaluation.decision == EvidenceQualificationEvaluation.Decision.REVOKED
    assert evaluation.qualified is False
    ctx['finding'].refresh_from_db()
    assert ctx['finding'].status == 'open'
