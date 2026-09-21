from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from enterprise.campaign_models import AdversaryCampaign, CampaignAuditEvent, CampaignObjective, CampaignObjectiveAssessment
from enterprise.models import AttackPath, AttackPathValidation, BlastRadiusSnapshot, OrganizationMembership, TenantProject
from fastapi_app.services.authorization_guard import current_asset_authorization


_POLICY_VERSION = 'campaign-objective.v1'
_GOVERNANCE_ROLES = {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN, OrganizationMembership.Role.MANAGER}
_ASSESS_ROLES = _GOVERNANCE_ROLES | {OrganizationMembership.Role.ANALYST}
_READ_ROLES = set(OrganizationMembership.Role.values)
_OUTCOMES = {value for value, _ in CampaignObjectiveAssessment.Outcome.choices}


class CampaignAssuranceError(ValueError):
    pass


class StaleCampaignVersion(CampaignAssuranceError):
    pass


class StaleObjectiveVersion(CampaignAssuranceError):
    pass


@dataclass(frozen=True)
class AssessmentResult:
    assessment: CampaignObjectiveAssessment
    objective: CampaignObjective
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _membership(project_id: str, user_id: str, roles: set[str]):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None:
        raise CampaignAssuranceError('Project is not bound to an enterprise tenant.')
    membership = OrganizationMembership.objects.filter(
        organization=link.organization,
        user_id=user_id,
        is_active=True,
        user__is_active=True,
        role__in=roles,
    ).first()
    if membership is None:
        raise PermissionError('Active tenant role does not permit this campaign assurance operation.')
    return link, membership


def _membership_locked(project_id: str, user_id: str, roles: set[str]):
    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .select_related('organization', 'project')
        .filter(project_id=project_id)
        .first()
    )
    if link is None:
        raise CampaignAssuranceError('Project is not bound to an enterprise tenant.')
    membership = (
        OrganizationMembership.objects.select_for_update(of=('self',))
        .filter(
            organization=link.organization,
            user_id=user_id,
            is_active=True,
            user__is_active=True,
            role__in=roles,
        )
        .first()
    )
    if membership is None:
        raise PermissionError('Active tenant role does not permit this campaign assurance operation.')
    return link, membership


def _current_authorization_locked(asset: Asset, expected_target: str = '') -> AssetAuthorization:
    decision, reason = current_asset_authorization(asset, expected_target)
    if decision is None:
        raise CampaignAssuranceError(reason)
    locked = AssetAuthorization.objects.select_for_update().get(pk=decision.pk)
    if locked.authorized is not True or not locked.is_currently_valid:
        raise CampaignAssuranceError('Execution blocked: latest authorization decision is not currently valid.')
    return locked


def _authorized_asset_locked(project_id: str, asset_id: str, expected_target: str = ''):
    asset = Asset.objects.select_for_update().filter(pk=asset_id, project_id=project_id).first()
    if asset is None:
        raise CampaignAssuranceError('Campaign asset is outside the project scope.')
    decision = _current_authorization_locked(asset, expected_target)
    return asset, decision


def _append_event_locked(campaign: AdversaryCampaign, actor_id: str | None, event_type: str, payload: dict[str, Any]):
    previous = CampaignAuditEvent.objects.filter(campaign=campaign).order_by('-id').first()
    previous_hash = previous.entry_hash if previous else ''
    envelope = {
        'campaign_id': str(campaign.id),
        'actor_id': str(actor_id or ''),
        'event_type': event_type,
        'payload': payload,
        'previous_hash': previous_hash,
    }
    return CampaignAuditEvent.objects.create(
        campaign=campaign,
        actor_id=actor_id,
        event_type=event_type,
        payload=payload,
        previous_hash=previous_hash,
        entry_hash=_sha(envelope),
    )


def create_campaign(*, project_id: str, user_id: str, name: str, source_asset_id: str) -> AdversaryCampaign:
    normalized_name = ' '.join(str(name or '').split())
    if not normalized_name:
        raise CampaignAssuranceError('Campaign name is required.')
    with transaction.atomic():
        link, _ = _membership_locked(project_id, user_id, _GOVERNANCE_ROLES)
        source_asset, authorization = _authorized_asset_locked(project_id, source_asset_id)
        scope_sha256 = _sha({
            'project_id': str(project_id),
            'source_asset_id': str(source_asset.id),
            'authorization_decision_id': str(authorization.id),
            'target_snapshot': authorization.target_snapshot,
        })
        campaign = AdversaryCampaign.objects.create(
            organization=link.organization,
            project_id=project_id,
            name=normalized_name,
            source_asset=source_asset,
            scope_sha256=scope_sha256,
            created_by_id=user_id,
        )
        _append_event_locked(campaign, user_id, 'campaign.created', {
            'name': normalized_name,
            'source_asset_id': str(source_asset.id),
            'scope_sha256': scope_sha256,
            'authorization_decision_id': str(authorization.id),
        })
        return campaign


def add_objective(*, campaign_id: str, project_id: str, user_id: str, expected_campaign_version: int, target_asset_id: str, title: str, objective_type: str = 'crown_jewel_access', success_criteria: dict[str, Any] | None = None, attack_techniques: list[str] | None = None) -> tuple[CampaignObjective, bool]:
    normalized_title = ' '.join(str(title or '').split())
    if not normalized_title:
        raise CampaignAssuranceError('Objective title is required.')
    techniques = sorted({str(item).strip() for item in (attack_techniques or []) if str(item).strip()})
    with transaction.atomic():
        link, _ = _membership_locked(project_id, user_id, _GOVERNANCE_ROLES)
        campaign = AdversaryCampaign.objects.select_for_update().filter(
            pk=campaign_id,
            project_id=project_id,
            organization=link.organization,
        ).first()
        if campaign is None:
            raise CampaignAssuranceError('Campaign not found in project.')
        if campaign.status != AdversaryCampaign.Status.ACTIVE:
            raise CampaignAssuranceError('Objectives may only be added to an active campaign.')
        source_asset, source_authorization = _authorized_asset_locked(project_id, str(campaign.source_asset_id))
        if str(source_asset.id) == str(target_asset_id):
            target_asset, authorization = source_asset, source_authorization
        else:
            target_asset, authorization = _authorized_asset_locked(project_id, target_asset_id)
        existing = CampaignObjective.objects.filter(campaign=campaign, target_asset=target_asset).first()
        if existing is not None:
            same = existing.title == normalized_title and existing.objective_type == objective_type and existing.success_criteria == (success_criteria or {}) and existing.attack_techniques == techniques
            if same:
                return existing, True
            raise CampaignAssuranceError('Campaign already has a different objective for this target asset.')
        if campaign.version != expected_campaign_version:
            raise StaleCampaignVersion(f'Expected campaign version {expected_campaign_version}, current version is {campaign.version}.')
        objective = CampaignObjective.objects.create(
            campaign=campaign,
            target_asset=target_asset,
            title=normalized_title,
            objective_type=objective_type,
            success_criteria=success_criteria or {},
            attack_techniques=techniques,
            created_by_id=user_id,
        )
        campaign.version += 1
        campaign.save(update_fields=['version', 'updated_at'])
        _append_event_locked(campaign, user_id, 'objective.created', {
            'objective_id': str(objective.id),
            'target_asset_id': str(target_asset.id),
            'objective_type': objective.objective_type,
            'attack_techniques': techniques,
            'source_authorization_decision_id': str(source_authorization.id),
            'authorization_decision_id': str(authorization.id),
            'campaign_version': campaign.version,
        })
        return objective, False


def _path_asset_id(node: Any) -> str:
    if isinstance(node, dict):
        return str(node.get('asset_id') or node.get('id') or '').strip()
    if isinstance(node, str):
        return node.strip()
    return ''


def _path_step_ids(attack_path: AttackPath) -> list[str]:
    values = []
    for item in attack_path.steps or []:
        value = _path_asset_id(item) if isinstance(item, dict) else str(item).strip()
        if value:
            values.append(value)
    return values


def _path_asset_ids(attack_path: AttackPath) -> set[str]:
    values = {_path_asset_id(attack_path.source_node), _path_asset_id(attack_path.target_node)}
    values.update(_path_step_ids(attack_path))
    return {value for value in values if value}


def assess_objective(*, objective_id: str, campaign_id: str, project_id: str, user_id: str, expected_objective_version: int, attack_path_id: str, evidence_id: str, outcome: str, reason_code: str, explanation: str = '', blast_radius_snapshot_id: str | None = None, validation_id: str | None = None) -> AssessmentResult:
    if outcome not in _OUTCOMES:
        raise CampaignAssuranceError('Outcome must be reached, blocked, or inconclusive.')
    reason = str(reason_code or '').strip()
    if not reason:
        raise CampaignAssuranceError('reason_code is required.')
    with transaction.atomic():
        link, _ = _membership_locked(project_id, user_id, _ASSESS_ROLES)
        objective = (
            CampaignObjective.objects.select_for_update(of=('self',))
            .select_related('campaign', 'campaign__source_asset', 'target_asset')
            .filter(pk=objective_id, campaign_id=campaign_id, campaign__project_id=project_id, campaign__organization=link.organization)
            .first()
        )
        if objective is None:
            raise CampaignAssuranceError('Campaign objective not found in tenant/project scope.')
        campaign = AdversaryCampaign.objects.select_for_update().get(pk=objective.campaign_id)
        if campaign.status != AdversaryCampaign.Status.ACTIVE:
            raise CampaignAssuranceError('Objective assessment requires an active campaign.')

        source_asset, source_authorization = _authorized_asset_locked(project_id, str(campaign.source_asset_id))
        if str(objective.target_asset_id) == str(source_asset.id):
            target_asset, target_authorization = source_asset, source_authorization
        else:
            target_asset, target_authorization = _authorized_asset_locked(project_id, str(objective.target_asset_id))

        attack_path = AttackPath.objects.select_for_update().filter(
            pk=attack_path_id,
            project_id=project_id,
            organization=link.organization,
        ).first()
        if attack_path is None:
            raise CampaignAssuranceError('Attack path is outside the campaign tenant/project scope.')
        source_id = _path_asset_id(attack_path.source_node)
        target_id = _path_asset_id(attack_path.target_node)
        if source_id != str(campaign.source_asset_id) or target_id != str(objective.target_asset_id):
            raise CampaignAssuranceError('Attack path source/target do not match the campaign objective.')
        steps = _path_step_ids(attack_path)
        if steps and (steps[0] != str(campaign.source_asset_id) or steps[-1] != str(objective.target_asset_id)):
            raise CampaignAssuranceError('Attack path step lineage does not terminate at the objective crown jewel.')
        path_asset_ids = _path_asset_ids(attack_path)

        evidence = (
            Evidence.objects.select_for_update(of=('self',))
            .select_related('asset', 'finding', 'finding__asset')
            .filter(pk=evidence_id, asset__project_id=project_id)
            .first()
        )
        if evidence is None:
            raise CampaignAssuranceError('Evidence is outside the campaign project scope.')
        if str(evidence.asset_id) not in path_asset_ids:
            raise CampaignAssuranceError('Evidence asset is not part of the assessed AttackPath lineage.')
        if evidence.finding_id:
            if str(evidence.finding.project_id) != str(project_id):
                raise CampaignAssuranceError('Evidence finding is outside the campaign project scope.')
            if evidence.finding.asset_id and str(evidence.finding.asset_id) != str(evidence.asset_id):
                raise CampaignAssuranceError('Evidence finding asset does not match the evidence asset lineage.')
        raw_sha = hashlib.sha256((evidence.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
        if evidence.sha256 and raw_sha != evidence.sha256:
            raise CampaignAssuranceError('Evidence integrity check failed.')

        authorization_by_asset = {
            str(source_asset.id): source_authorization,
            str(target_asset.id): target_authorization,
        }
        evidence_authorization = authorization_by_asset.get(str(evidence.asset_id))
        if evidence_authorization is None:
            _, evidence_authorization = _authorized_asset_locked(project_id, str(evidence.asset_id))

        validation = None
        if validation_id:
            validation = (
                ValidationRun.objects.select_for_update(of=('self',))
                .select_related('finding', 'finding__asset', 'authorization_decision')
                .filter(pk=validation_id, status=ValidationRun.Status.COMPLETED)
                .first()
            )
            if validation is None:
                raise CampaignAssuranceError('Objective validation must be a completed ValidationRun.')
            if not validation.finding_id or not evidence.finding_id:
                raise CampaignAssuranceError('ValidationRun and evidence must both be bound to the same finding.')
            if str(validation.finding.project_id) != str(project_id):
                raise CampaignAssuranceError('ValidationRun is outside the campaign project scope.')
            if validation.finding_id != evidence.finding_id:
                raise CampaignAssuranceError('ValidationRun finding does not match the evidence finding lineage.')
            if validation.finding.asset_id and str(validation.finding.asset_id) != str(evidence.asset_id):
                raise CampaignAssuranceError('ValidationRun finding asset does not match the evidence asset lineage.')
            if validation.authorized is not True or not validation.authorization_decision_id:
                raise CampaignAssuranceError('ValidationRun is not bound to an authorized asset decision.')
            evidence_authorization = _current_authorization_locked(evidence.asset, validation.target_value)
            if validation.authorization_decision_id != evidence_authorization.id:
                raise CampaignAssuranceError('ValidationRun authorization is no longer the current evidence-asset decision.')

        if outcome == CampaignObjectiveAssessment.Outcome.REACHED and attack_path.status != AttackPath.Status.VALIDATED:
            raise CampaignAssuranceError('Reached outcome requires a validated AttackPath.')

        blast = None
        blast_evidence_refs: list[str] = []
        if blast_radius_snapshot_id:
            blast = BlastRadiusSnapshot.objects.select_for_update().filter(
                pk=blast_radius_snapshot_id,
                project_id=project_id,
                organization=link.organization,
            ).first()
            if blast is None or blast.attack_path_id != attack_path.id:
                raise CampaignAssuranceError('Blast-radius snapshot must belong to the assessed AttackPath.')
            crown_jewel_refs = {str(item) for item in (blast.crown_jewel_refs or [])}
            if crown_jewel_refs and str(objective.target_asset_id) not in crown_jewel_refs:
                raise CampaignAssuranceError('Blast-radius snapshot does not include the objective crown jewel.')
            blast_evidence_refs = sorted({str(item) for item in (blast.evidence_refs or [])})
            if blast_evidence_refs and str(evidence.id) not in blast_evidence_refs:
                raise CampaignAssuranceError('Blast-radius evidence refs do not include the assessment evidence.')
            attack_validation = AttackPathValidation.objects.filter(
                project_id=project_id,
                organization=link.organization,
                attack_path=attack_path,
                blast_radius_snapshot=blast,
            ).order_by('-created_at', '-id').first()
            if attack_validation is None:
                raise CampaignAssuranceError('Blast-radius snapshot is not backed by immutable AttackPathValidation.')
            validation_evidence_refs = {str(item) for item in (attack_validation.evidence_refs or [])}
            if str(evidence.id) not in validation_evidence_refs:
                raise CampaignAssuranceError('AttackPathValidation evidence refs do not include the assessment evidence.')

        proof_material = {
            'policy_version': _POLICY_VERSION,
            'campaign_id': str(campaign.id),
            'objective_id': str(objective.id),
            'source_authorization_decision_id': str(source_authorization.id),
            'target_authorization_decision_id': str(target_authorization.id),
            'attack_path_id': str(attack_path.id),
            'attack_path_status': attack_path.status,
            'path_risk_score': float(attack_path.risk_score or 0),
            'blast_radius_snapshot_id': str(blast.id) if blast else '',
            'blast_radius_score': float(blast.score or 0) if blast else 0.0,
            'blast_evidence_refs': blast_evidence_refs,
            'evidence_id': str(evidence.id),
            'evidence_asset_id': str(evidence.asset_id),
            'evidence_finding_id': str(evidence.finding_id or ''),
            'evidence_authorization_decision_id': str(evidence_authorization.id),
            'evidence_sha256': evidence.sha256 or raw_sha,
            'validation_id': str(validation.id) if validation else '',
            'validation_finding_id': str(validation.finding_id) if validation else '',
            'validation_authorization_decision_id': str(validation.authorization_decision_id) if validation else '',
            'outcome': outcome,
            'reason_code': reason,
            'explanation': str(explanation or '').strip(),
        }
        proof_sha256 = _sha(proof_material)
        replay_fingerprint = _sha({'objective_id': str(objective.id), 'proof_sha256': proof_sha256})
        existing = CampaignObjectiveAssessment.objects.filter(replay_fingerprint=replay_fingerprint).first()
        if existing is not None:
            return AssessmentResult(existing, objective, True)
        if objective.version != expected_objective_version:
            raise StaleObjectiveVersion(f'Expected objective version {expected_objective_version}, current version is {objective.version}.')
        prior = objective.assessments.order_by('-assessed_at', '-id').first()
        generation = objective.generation
        if prior is not None and prior.outcome != outcome:
            generation += 1
        next_version = objective.version + 1
        assessment = CampaignObjectiveAssessment.objects.create(
            objective=objective,
            attack_path=attack_path,
            blast_radius_snapshot=blast,
            evidence=evidence,
            validation_run=validation,
            outcome=outcome,
            reason_code=reason,
            explanation=str(explanation or '').strip(),
            path_risk_score=float(attack_path.risk_score or 0),
            blast_radius_score=float(blast.score or 0) if blast else 0.0,
            objective_generation=generation,
            objective_version=next_version,
            proof_sha256=proof_sha256,
            replay_fingerprint=replay_fingerprint,
            policy_version=_POLICY_VERSION,
            assessed_by_id=user_id,
        )
        objective.status = outcome
        objective.generation = generation
        objective.version = next_version
        objective.save(update_fields=['status', 'generation', 'version', 'updated_at'])
        campaign.version += 1
        campaign.save(update_fields=['version', 'updated_at'])
        _append_event_locked(campaign, user_id, 'objective.assessed', {
            'objective_id': str(objective.id),
            'assessment_id': str(assessment.id),
            'outcome': outcome,
            'reason_code': reason,
            'proof_sha256': proof_sha256,
            'attack_path_id': str(attack_path.id),
            'evidence_id': str(evidence.id),
            'validation_id': str(validation.id) if validation else '',
            'blast_radius_snapshot_id': str(blast.id) if blast else '',
            'source_authorization_decision_id': str(source_authorization.id),
            'target_authorization_decision_id': str(target_authorization.id),
            'evidence_authorization_decision_id': str(evidence_authorization.id),
            'path_risk_score': assessment.path_risk_score,
            'blast_radius_score': assessment.blast_radius_score,
            'objective_generation': generation,
            'objective_version': next_version,
            'campaign_version': campaign.version,
        })
        return AssessmentResult(assessment, objective, False)


def complete_campaign(*, campaign_id: str, project_id: str, user_id: str, expected_campaign_version: int) -> AdversaryCampaign:
    with transaction.atomic():
        link, _ = _membership_locked(project_id, user_id, _GOVERNANCE_ROLES)
        campaign = AdversaryCampaign.objects.select_for_update().filter(
            pk=campaign_id,
            project_id=project_id,
            organization=link.organization,
        ).first()
        if campaign is None:
            raise CampaignAssuranceError('Campaign not found in project.')
        if campaign.status == AdversaryCampaign.Status.COMPLETED:
            return campaign
        if campaign.status != AdversaryCampaign.Status.ACTIVE:
            raise CampaignAssuranceError('Only an active campaign can be completed.')
        if campaign.version != expected_campaign_version:
            raise StaleCampaignVersion(f'Expected campaign version {expected_campaign_version}, current version is {campaign.version}.')
        objectives = list(CampaignObjective.objects.filter(campaign=campaign).order_by('id'))
        if not objectives:
            raise CampaignAssuranceError('Campaign requires at least one objective before completion.')
        if any(item.status == CampaignObjective.Status.PENDING for item in objectives):
            raise CampaignAssuranceError('Every campaign objective requires a governed assessment before completion.')

        source_asset, source_authorization = _authorized_asset_locked(project_id, str(campaign.source_asset_id))
        authorization_snapshot = {'source': str(source_authorization.id), 'targets': {}}
        for target_asset_id in sorted({str(item.target_asset_id) for item in objectives}):
            if target_asset_id == str(source_asset.id):
                target_authorization = source_authorization
            else:
                _, target_authorization = _authorized_asset_locked(project_id, target_asset_id)
            authorization_snapshot['targets'][target_asset_id] = str(target_authorization.id)

        outcomes = {status: sum(1 for item in objectives if item.status == status) for status in (CampaignObjective.Status.REACHED, CampaignObjective.Status.BLOCKED, CampaignObjective.Status.INCONCLUSIVE)}
        latest = []
        for item in objectives:
            assessment = item.assessments.order_by('-assessed_at', '-id').first()
            latest.append({'objective_id': str(item.id), 'status': item.status, 'assessment_id': str(assessment.id) if assessment else '', 'proof_sha256': assessment.proof_sha256 if assessment else ''})
        completion_sha256 = _sha({
            'campaign_id': str(campaign.id),
            'outcomes': outcomes,
            'objectives': latest,
            'authorization_snapshot': authorization_snapshot,
        })
        campaign.status = AdversaryCampaign.Status.COMPLETED
        campaign.completed_at = timezone.now()
        campaign.completion_sha256 = completion_sha256
        campaign.version += 1
        campaign.save(update_fields=['status', 'completed_at', 'completion_sha256', 'version', 'updated_at'])
        _append_event_locked(campaign, user_id, 'campaign.completed', {
            'outcomes': outcomes,
            'objective_count': len(objectives),
            'completion_sha256': completion_sha256,
            'authorization_snapshot': authorization_snapshot,
            'campaign_version': campaign.version,
        })
        return campaign


def campaign_summary(*, campaign_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, _READ_ROLES)
    campaign = AdversaryCampaign.objects.select_related('source_asset').filter(pk=campaign_id, project_id=project_id).first()
    if campaign is None:
        raise CampaignAssuranceError('Campaign not found in project.')
    objectives = []
    for objective in CampaignObjective.objects.filter(campaign=campaign).select_related('target_asset').order_by('created_at', 'id'):
        latest = objective.assessments.select_related('attack_path', 'blast_radius_snapshot', 'evidence', 'validation_run').order_by('-assessed_at', '-id').first()
        objectives.append({
            'id': str(objective.id),
            'title': objective.title,
            'target_asset_id': str(objective.target_asset_id),
            'status': objective.status,
            'generation': objective.generation,
            'version': objective.version,
            'latest_assessment': None if latest is None else {
                'id': str(latest.id),
                'outcome': latest.outcome,
                'reason_code': latest.reason_code,
                'attack_path_id': str(latest.attack_path_id),
                'evidence_id': str(latest.evidence_id),
                'validation_id': str(latest.validation_run_id) if latest.validation_run_id else None,
                'blast_radius_snapshot_id': str(latest.blast_radius_snapshot_id) if latest.blast_radius_snapshot_id else None,
                'proof_sha256': latest.proof_sha256,
                'path_risk_score': latest.path_risk_score,
                'blast_radius_score': latest.blast_radius_score,
            },
        })
    return {
        'id': str(campaign.id),
        'name': campaign.name,
        'project_id': str(campaign.project_id),
        'source_asset_id': str(campaign.source_asset_id),
        'status': campaign.status,
        'version': campaign.version,
        'scope_sha256': campaign.scope_sha256,
        'completion_sha256': campaign.completion_sha256,
        'objectives': objectives,
    }


def verify_campaign_chain(*, campaign_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, _READ_ROLES)
    campaign = AdversaryCampaign.objects.filter(pk=campaign_id, project_id=project_id).first()
    if campaign is None:
        raise CampaignAssuranceError('Campaign not found in project.')
    previous = ''
    rows = list(CampaignAuditEvent.objects.filter(campaign=campaign).order_by('id'))
    for row in rows:
        if row.previous_hash != previous:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'previous_hash'}
        envelope = {'campaign_id': str(campaign.id), 'actor_id': str(row.actor_id or ''), 'event_type': row.event_type, 'payload': row.payload, 'previous_hash': row.previous_hash}
        expected = _sha(envelope)
        if row.entry_hash != expected:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'entry_hash'}
        previous = row.entry_hash
    return {'valid': True, 'entries': len(rows), 'head': previous}
