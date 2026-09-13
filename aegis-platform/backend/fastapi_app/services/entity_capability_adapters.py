from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from django.db.models import Q
from django.utils import timezone as django_timezone

from django_project.assets.models import AssetAuthorization
from django_project.evidence.models import Evidence, FindingDisposition, ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from enterprise.assurance_obligation_models import AssuranceObligation
from enterprise.campaign_models import AdversaryCampaign, CampaignObjective
from enterprise.detection_models import DetectionRevision, DetectionValidation
from enterprise.models import AttackPath, ExternalIntegration, InvestigationCase, RiskCorrelationSnapshot, TenantProject
from enterprise.soc_models import InvestigationCaseState, InvestigationClosure
from fastapi_app.contracts.governed_operations import (
    ActionMode,
    AuthoritativeCapabilityManifest,
    CapabilityItem,
    EntityRef,
    GateResult,
    GateState,
    GateType,
    ProjectionSnapshot,
)
from fastapi_app.services.authorization_guard import asset_target, current_asset_authorization
from fastapi_app.services.governed_operations import evaluate_action, list_action_contracts
from fastapi_app.services.governed_responsibility_authority import (
    GovernedResponsibilityError,
    resolve_actor_authority,
)
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state


POLICY_VERSION = 'agom-entity-capability.v1'
_SIEM_KINDS = {
    ExternalIntegration.Kind.SPLUNK,
    ExternalIntegration.Kind.ELASTIC,
    ExternalIntegration.Kind.SENTINEL,
    ExternalIntegration.Kind.QRADAR,
}


class EntityCapabilityError(ValueError):
    pass


class EntityCapabilityNotFound(EntityCapabilityError):
    pass


@dataclass(frozen=True)
class HardBlock:
    reason_code: str
    reason: str
    missing_requirements: tuple[str, ...] = ()


@dataclass
class EntityCapabilityContext:
    organization_id: str
    entity: EntityRef
    projection: ProjectionSnapshot
    evidence_ready_actions: set[str] = field(default_factory=set)
    sod_eligible_actions: set[str] = field(default_factory=set)
    gate_results_by_action: dict[str, list[GateResult]] = field(default_factory=dict)
    hard_blocks: dict[str, HardBlock] = field(default_factory=dict)


def _gate(
    gate: GateType,
    state: GateState,
    reason_code: str,
    reason: str,
    *,
    missing: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> GateResult:
    return GateResult(
        gate=gate,
        state=state,
        reason_code=reason_code,
        reason=reason,
        missing_requirements=missing or [],
        evidence_refs=evidence_refs or [],
        policy_version=POLICY_VERSION,
        evaluated_at=django_timezone.now(),
    )


def _tenant_link_for_actor(*, project_id: str, user_id: str) -> TenantProject:
    link = (
        TenantProject.objects.select_related('organization', 'project')
        .filter(project_id=project_id, organization__is_active=True)
        .first()
    )
    if link is None:
        raise EntityCapabilityNotFound('Entity capability scope not found.')
    try:
        resolve_actor_authority(
            organization_id=str(link.organization_id),
            user_id=str(user_id),
            project_id=str(link.project_id),
        )
    except (PermissionError, GovernedResponsibilityError) as exc:
        raise EntityCapabilityNotFound('Entity capability scope not found.') from exc
    return link


def _entity_ref(*, entity_type: str, entity_id: Any, link: TenantProject) -> EntityRef:
    return EntityRef(
        entity_type=entity_type,
        entity_id=str(entity_id),
        tenant_id=str(link.organization_id),
        project_id=str(link.project_id),
    )


def _authorization_gate(assets: list[Any]) -> GateResult:
    refs: list[str] = []
    missing: list[str] = []
    seen: set[str] = set()
    for asset in assets:
        if asset is None or str(asset.id) in seen:
            continue
        seen.add(str(asset.id))
        decision, reason = current_asset_authorization(asset, asset_target(asset))
        if decision is None:
            missing.append(f'asset:{asset.id}:{reason}')
            continue
        refs.append(str(decision.id))
    if missing:
        return _gate(
            GateType.AUTHORIZATION,
            GateState.FAIL,
            'CURRENT_AUTHORIZATION_MISSING',
            'One or more entity assets do not have a current authorization decision for their current target.',
            missing=missing,
            evidence_refs=refs,
        )
    if not refs:
        return _gate(
            GateType.AUTHORIZATION,
            GateState.BLOCKED,
            'AUTHORIZED_ASSET_REQUIRED',
            'The governed action has no authoritative asset authorization lineage.',
            missing=['current_asset_authorization'],
        )
    return _gate(
        GateType.AUTHORIZATION,
        GateState.PASS,
        'CURRENT_AUTHORIZATION_VALID',
        'All entity assets are bound to current authorization decisions.',
        evidence_refs=refs,
    )


def _path_asset_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get('asset_id') or value.get('id') or '').strip()
    return str(value or '').strip()


def _path_asset_ids(path: AttackPath) -> set[str]:
    values = {_path_asset_id(path.source_node), _path_asset_id(path.target_node)}
    for step in path.steps or []:
        values.add(_path_asset_id(step))
    return {item for item in values if item}


def _objective_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    objective = (
        CampaignObjective.objects.select_related('campaign', 'campaign__source_asset', 'target_asset')
        .filter(pk=entity_id, campaign__project_id=link.project_id, campaign__organization=link.organization)
        .first()
    )
    if objective is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    campaign = objective.campaign
    if campaign.status != AdversaryCampaign.Status.ACTIVE:
        lifecycle = campaign.status
    elif objective.assessments.exists():
        lifecycle = 'assessing'
    else:
        lifecycle = 'defined'

    action = 'campaign.objective.assess'
    authorization = _authorization_gate([campaign.source_asset, objective.target_asset])
    paths = list(
        AttackPath.objects.filter(
            organization=link.organization,
            project_id=link.project_id,
        ).order_by('-updated_at', '-discovered_at')
    )
    candidates: list[tuple[AttackPath, Evidence]] = []
    for path in paths:
        if _path_asset_id(path.source_node) != str(campaign.source_asset_id):
            continue
        if _path_asset_id(path.target_node) != str(objective.target_asset_id):
            continue
        asset_ids = _path_asset_ids(path)
        evidences = (
            Evidence.objects.select_related('finding', 'asset')
            .filter(asset_id__in=asset_ids)
            .filter(Q(finding__isnull=True) | Q(finding__project_id=link.project_id))
            .order_by('-collected_at')[:50]
        )
        for evidence in evidences:
            if evidence.asset_id is None:
                continue
            if evidence.finding_id and evidence.finding.asset_id and str(evidence.finding.asset_id) != str(evidence.asset_id):
                continue
            expected_sha = hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest()
            if expected_sha != evidence.sha256:
                continue
            candidates.append((path, evidence))
            break

    evidence_refs = [str(evidence.id) for _path, evidence in candidates]
    path_refs = [str(path.id) for path, _evidence in candidates]
    evidence_ready = bool(candidates)
    assessable_paths = [
        path for path, _evidence in candidates
        if path.status in {AttackPath.Status.DISCOVERED, AttackPath.Status.VALIDATED}
    ]
    evidence_gate = _gate(
        GateType.EVIDENCE,
        GateState.PASS if evidence_ready else GateState.BLOCKED,
        'OBJECTIVE_EVIDENCE_CANDIDATE_READY' if evidence_ready else 'OBJECTIVE_EVIDENCE_REQUIRED',
        'At least one tenant-scoped AttackPath has lineage-consistent, hash-valid objective evidence.' if evidence_ready else 'No lineage-consistent AttackPath/evidence candidate is available for objective assessment.',
        missing=[] if evidence_ready else ['attack_path', 'objective_evidence'],
        evidence_refs=path_refs + evidence_refs,
    )
    validation_gate = _gate(
        GateType.VALIDATION,
        GateState.PASS if assessable_paths else GateState.BLOCKED,
        'ASSESSABLE_ATTACK_PATH_READY' if assessable_paths else 'ASSESSABLE_ATTACK_PATH_REQUIRED',
        'An AttackPath candidate is available for governed assessment; outcome-specific validation remains enforced by the campaign command.' if assessable_paths else 'Objective assessment requires a discovered or validated AttackPath candidate.',
        missing=[] if assessable_paths else ['assessable_attack_path'],
        evidence_refs=[str(item.id) for item in assessable_paths],
    )
    context = EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='crown_jewel_objective', entity_id=objective.id, link=link),
        projection=ProjectionSnapshot(
            lifecycle=lifecycle,
            outcome=objective.status if objective.status != CampaignObjective.Status.PENDING else None,
            version=objective.version,
        ),
        gate_results_by_action={action: [authorization, evidence_gate, validation_gate]},
    )
    if evidence_ready:
        context.evidence_ready_actions.add(action)
    return context


def _campaign_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    campaign = (
        AdversaryCampaign.objects.select_related('source_asset')
        .filter(pk=entity_id, project_id=link.project_id, organization=link.organization)
        .first()
    )
    if campaign is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    objectives = list(campaign.objectives.select_related('target_asset').order_by('id'))
    latest = [item.assessments.order_by('-assessed_at', '-id').first() for item in objectives]
    lifecycle = campaign.status
    if campaign.status == AdversaryCampaign.Status.ACTIVE and any(item is not None for item in latest):
        lifecycle = 'assessing'

    action = 'campaign.complete'
    authorization = _authorization_gate([campaign.source_asset, *[item.target_asset for item in objectives]])
    terminal = bool(objectives) and all(item.status != CampaignObjective.Status.PENDING for item in objectives)
    complete_proofs = terminal and all(item is not None and bool(item.proof_sha256) for item in latest)
    closure_gate = _gate(
        GateType.CLOSURE,
        GateState.PASS if terminal else GateState.BLOCKED,
        'OBJECTIVES_TERMINAL' if terminal else 'OBJECTIVES_NOT_TERMINAL',
        'All campaign objectives have terminal governed assessments.' if terminal else 'Campaign completion requires at least one objective and no pending objectives.',
        missing=[] if terminal else ['terminal_objective_assessments'],
        evidence_refs=[str(item.id) for item in latest if item is not None],
    )
    evidence_gate = _gate(
        GateType.EVIDENCE,
        GateState.PASS if complete_proofs else GateState.BLOCKED,
        'COMPLETION_PROOF_READY' if complete_proofs else 'COMPLETION_PROOF_INCOMPLETE',
        'Every terminal objective is bound to an immutable assessment proof.' if complete_proofs else 'Campaign completion proof is incomplete.',
        missing=[] if complete_proofs else ['completion_proof'],
        evidence_refs=[item.proof_sha256 for item in latest if item is not None and item.proof_sha256],
    )
    assessors = {str(item.assessed_by_id) for item in latest if item is not None}
    sod_eligible = bool(latest) and all(item is not None for item in latest) and not (
        len(assessors) == 1 and str(actor_id) in assessors
    )
    context = EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='campaign', entity_id=campaign.id, link=link),
        projection=ProjectionSnapshot(lifecycle=lifecycle, version=campaign.version),
        gate_results_by_action={action: [authorization, closure_gate, evidence_gate]},
    )
    if complete_proofs:
        context.evidence_ready_actions.add(action)
    if sod_eligible:
        context.sod_eligible_actions.add(action)
    return context


def _latest_validation(finding: Vulnerability) -> ValidationRun | None:
    return (
        ValidationRun.objects.select_related('authorization_decision', 'finding__asset')
        .filter(finding=finding)
        .order_by('-created_at', '-id')
        .first()
    )


def _confirmation_candidate(finding: Vulnerability) -> tuple[ValidationRun, Evidence] | None:
    if not finding.asset_id:
        return None
    validation = _latest_validation(finding)
    if validation is None:
        return None
    if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
        return None
    if not validation.authorization_decision_id:
        return None
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not True:
        return None
    evidence_id = result.get('evidence_id')
    if not evidence_id:
        return None
    evidence = Evidence.objects.filter(pk=evidence_id, finding=finding, evidence_type='validation_output').first()
    if evidence is None:
        return None
    expected_sha = hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest()
    if expected_sha != evidence.sha256:
        return None
    metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
    if str(metadata.get('validation_run_id') or metadata.get('validation_id') or '') != str(validation.id):
        return None
    if metadata.get('finding_present') is not True:
        return None
    if str(metadata.get('authorization_decision_id') or '') != str(validation.authorization_decision_id):
        return None
    decision, _reason = current_asset_authorization(finding.asset, validation.target_value)
    if decision is None or decision.id != validation.authorization_decision_id:
        return None
    return validation, evidence


def _verified_remediation(finding: Vulnerability) -> tuple[ValidationRun, Evidence] | None:
    validation = _latest_validation(finding)
    if validation is None:
        return None
    if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
        return None
    if not validation.authorization_decision_id:
        return None
    if get_state(validation) != RemediationState.VERIFIED:
        return None
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not False:
        return None
    evidence_id = result.get('evidence_id')
    evidence = Evidence.objects.filter(pk=evidence_id, finding=finding).first() if evidence_id else None
    if evidence is None:
        return None
    expected_sha = hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest()
    if expected_sha != evidence.sha256:
        return None
    if finding.asset_id:
        decision, _reason = current_asset_authorization(finding.asset, validation.target_value)
        if decision is None or decision.id != validation.authorization_decision_id:
            return None
    return validation, evidence


def _finding_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    finding = (
        Vulnerability.objects.select_related('scan', 'asset')
        .filter(pk=entity_id, project_id=link.project_id)
        .first()
    )
    if finding is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    confirmation = _confirmation_candidate(finding)
    verified = _verified_remediation(finding)
    if verified is not None:
        lifecycle = 'verified'
    elif finding.status == Vulnerability.Status.OPEN:
        lifecycle = 'pending_confirmation'
    elif finding.status == Vulnerability.Status.FIXED:
        lifecycle = 'closed'
    else:
        lifecycle = finding.status

    gates: dict[str, list[GateResult]] = {}
    evidence_ready: set[str] = set()
    sod: set[str] = set()

    confirm_action = 'finding.confirm'
    confirm_refs = [str(confirmation[0].id), str(confirmation[1].id)] if confirmation else []
    gates[confirm_action] = [_gate(
        GateType.EVIDENCE,
        GateState.PASS if confirmation else GateState.BLOCKED,
        'CONFIRMATION_EVIDENCE_READY' if confirmation else 'CONFIRMATION_EVIDENCE_REQUIRED',
        'The latest validation is current, authorized, finding-present, and bound to lineage-consistent confirmation evidence.' if confirmation else 'Finding confirmation requires the latest validation to be completed, authorized, finding-present, and bound to current validation_output evidence.',
        missing=[] if confirmation else ['latest_finding_present_validation', 'finding_confirmation_evidence'],
        evidence_refs=confirm_refs,
    )]
    if confirmation:
        evidence_ready.add(confirm_action)
    creator_id = str(finding.scan.initiated_by_id or '')
    if creator_id and creator_id != str(actor_id):
        sod.add(confirm_action)

    risk_action = 'finding.disposition.accept_risk'
    risk = RiskCorrelationSnapshot.objects.filter(
        project_id=link.project_id,
        vulnerability=finding,
    ).order_by('-created_at', '-id').first()
    gates[risk_action] = [
        _gate(
            GateType.EVIDENCE,
            GateState.PASS if risk else GateState.BLOCKED,
            'RISK_SNAPSHOT_READY' if risk else 'RISK_SNAPSHOT_REQUIRED',
            'Latest immutable risk correlation snapshot is available.' if risk else 'Risk disposition requires an immutable risk correlation snapshot.',
            missing=[] if risk else ['risk_correlation_snapshot'],
            evidence_refs=[str(risk.id), risk.correlation_sha256] if risk else [],
        ),
        _gate(
            GateType.EXPIRY_REVIEW,
            GateState.BLOCKED,
            'REVIEW_DEADLINE_INPUT_REQUIRED',
            'Risk acceptance requires a future review_at value and rationale at execution time.',
            missing=['review_at', 'disposition_rationale'],
        ),
    ]
    if risk:
        evidence_ready.add(risk_action)

    close_action = 'finding.close'
    verifier_id = str(verified[0].user_id) if verified else ''
    independent = bool(verified) and verifier_id != str(actor_id)
    close_refs = [str(verified[0].id), str(verified[1].id)] if verified else []
    gates[close_action] = [
        _gate(
            GateType.CLOSURE,
            GateState.PASS if verified else GateState.BLOCKED,
            'LATEST_REMEDIATION_VERIFIED' if verified else 'LATEST_REMEDIATION_VERIFICATION_REQUIRED',
            'The latest finding validation is a current authorized VERIFIED remediation proof showing finding absence.' if verified else 'Finding closure requires the latest validation to be a current authorized VERIFIED remediation proof.',
            missing=[] if verified else ['latest_remediation_verification'],
            evidence_refs=close_refs,
        ),
        _gate(
            GateType.INDEPENDENT_VERIFICATION,
            GateState.PASS if independent else GateState.BLOCKED,
            'INDEPENDENT_VERIFIER' if independent else 'INDEPENDENT_VERIFIER_REQUIRED',
            'Closure actor is independent from the remediation verifier.' if independent else 'Closure actor must differ from the remediation verifier.',
            missing=[] if independent else ['independent_verifier'],
            evidence_refs=close_refs,
        ),
    ]
    if verified:
        evidence_ready.add(close_action)
    if independent:
        sod.add(close_action)

    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='finding', entity_id=finding.id, link=link),
        projection=ProjectionSnapshot(
            lifecycle=lifecycle,
            outcome=finding.validation_status or None,
            posture=finding.severity,
        ),
        evidence_ready_actions=evidence_ready,
        sod_eligible_actions=sod,
        gate_results_by_action=gates,
    )


def _detection_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    revision = (
        DetectionRevision.objects.select_related('rule')
        .filter(pk=entity_id, rule__project_id=link.project_id, rule__organization=link.organization)
        .first()
    )
    if revision is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    latest = revision.rule.revisions.order_by('-version').first()
    is_latest = latest is not None and latest.id == revision.id
    lifecycle = revision.rule.state if is_latest else 'superseded'
    passed = revision.validations.filter(status=DetectionValidation.Status.PASSED).order_by('-created_at').first()
    integration = ExternalIntegration.objects.filter(
        organization=link.organization,
        enabled=True,
        kind__in=_SIEM_KINDS,
    ).order_by('kind', 'id').first()
    action = 'detection.publish'
    validation_gate = _gate(
        GateType.VALIDATION,
        GateState.PASS if passed else GateState.BLOCKED,
        'DETECTION_VALIDATION_PASSED' if passed else 'DETECTION_VALIDATION_REQUIRED',
        'A passed telemetry validation is bound to this detection revision.' if passed else 'Detection publication requires a passed telemetry validation.',
        missing=[] if passed else ['passed_detection_validation'],
        evidence_refs=[str(passed.id), passed.result_sha256] if passed else [],
    )
    publication_gate = _gate(
        GateType.PUBLICATION,
        GateState.PASS if integration else GateState.BLOCKED,
        'SIEM_TARGET_AVAILABLE' if integration else 'SIEM_TARGET_REQUIRED',
        'At least one enabled tenant-owned SIEM publication target is available.' if integration else 'Detection publication requires an enabled tenant-owned SIEM integration.',
        missing=[] if integration else ['enabled_siem_integration'],
        evidence_refs=[str(integration.id)] if integration else [],
    )
    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='detection_revision', entity_id=revision.id, link=link),
        projection=ProjectionSnapshot(lifecycle=lifecycle, version=revision.version),
        evidence_ready_actions={action} if passed else set(),
        gate_results_by_action={action: [validation_gate, publication_gate]},
    )


def _investigation_proof(case: InvestigationCase, state: InvestigationCaseState | None) -> tuple[bool, list[str]]:
    refs: list[str] = []
    if state is not None and state.decision_action_id:
        refs.append(str(state.decision_action_id))
    for finding in case.findings.all():
        if state is not None and state.decision_action_id:
            verified = _verified_remediation(finding)
            if verified:
                refs.extend([str(verified[0].id), str(verified[1].id)])
                return True, refs
        disposition = FindingDisposition.objects.filter(finding=finding).order_by('-created_at', '-id').first()
        if disposition is None:
            continue
        if disposition.disposition in {FindingDisposition.Disposition.ACCEPTED_RISK, FindingDisposition.Disposition.WONT_FIX}:
            if disposition.review_at is None or disposition.review_at <= django_timezone.now():
                continue
        refs.append(str(disposition.id))
        return True, refs
    return False, refs


def _investigation_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    case = InvestigationCase.objects.filter(
        pk=entity_id,
        project_id=link.project_id,
        organization=link.organization,
    ).first()
    if case is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    state = InvestigationCaseState.objects.filter(case=case).first()
    existing = InvestigationClosure.objects.filter(case=case).first()
    proof_ready, refs = _investigation_proof(case, state)
    action = 'investigation.close'
    closure_ready = (
        case.status in {InvestigationCase.Status.INVESTIGATING, InvestigationCase.Status.DECIDED}
        and existing is None
        and state is not None
    )
    closure_gate = _gate(
        GateType.CLOSURE,
        GateState.PASS if closure_ready else GateState.BLOCKED,
        'CASE_CLOSURE_STATE_READY' if closure_ready else 'CASE_CLOSURE_STATE_BLOCKED',
        'Investigation state is eligible for governed closure.' if closure_ready else 'Governed closure requires an investigating/decided SOC-managed case that is not already closed.',
        missing=[] if closure_ready else ['soc_case_state', 'investigating_or_decided', 'not_already_closed'],
        evidence_refs=[str(state.case_id)] if state else [],
    )
    evidence_gate = _gate(
        GateType.EVIDENCE,
        GateState.PASS if proof_ready else GateState.BLOCKED,
        'CLOSURE_PROOF_CANDIDATE_READY' if proof_ready else 'CLOSURE_PROOF_REQUIRED',
        'At least one governed remediation or disposition closure proof is available.' if proof_ready else 'Investigation closure requires qualifying remediation or disposition proof.',
        missing=[] if proof_ready else ['response_evidence', 'closure_proof'],
        evidence_refs=refs,
    )
    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='investigation_case', entity_id=case.id, link=link),
        projection=ProjectionSnapshot(lifecycle=case.status, version=state.version if state else None),
        evidence_ready_actions={action} if proof_ready else set(),
        gate_results_by_action={action: [closure_gate, evidence_gate]},
    )


def _assurance_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    obligation = AssuranceObligation.objects.filter(
        pk=entity_id,
        project_id=link.project_id,
        organization=link.organization,
    ).first()
    if obligation is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    action = 'assurance.obligation.satisfy'
    evidence_refs = [str(obligation.last_observation_id)] if obligation.last_observation_id else []
    evidence_gate = _gate(
        GateType.EVIDENCE,
        GateState.BLOCKED,
        'AUTOMATIC_REVALIDATION_REQUIRED',
        'Assurance obligations are satisfied only by the governed revalidation pipeline after a later RESOLVED observation; no manual satisfaction mutation exists.',
        missing=['resolved_assurance_observation'],
        evidence_refs=evidence_refs,
    )
    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='assurance_obligation', entity_id=obligation.id, link=link),
        projection=ProjectionSnapshot(
            lifecycle=obligation.status,
            assurance=obligation.kind,
            version=obligation.version,
        ),
        gate_results_by_action={action: [evidence_gate]},
        hard_blocks={
            action: HardBlock(
                reason_code='AUTOMATIC_ONLY_ACTION',
                reason='This obligation is satisfied by authoritative assurance revalidation, not by a manual user action.',
                missing_requirements=('resolved_assurance_observation',),
            )
        },
    )


def _integration_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    integration = ExternalIntegration.objects.filter(pk=entity_id, organization=link.organization).first()
    if integration is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    action = 'integration.live_accept'
    live_gate = _gate(
        GateType.LIVE_ACCEPTANCE,
        GateState.BLOCKED,
        'LIVE_ACCEPTANCE_RECORD_NOT_IMPLEMENTED',
        'The integration domain has no authoritative tested/live-acceptance record yet; capability is fail-closed.',
        missing=['integration_acceptance_test', 'vendor_ack', 'acceptance_test_evidence'],
    )
    evidence_gate = _gate(
        GateType.EVIDENCE,
        GateState.BLOCKED,
        'ACCEPTANCE_EVIDENCE_NOT_MODELED',
        'No durable integration acceptance-evidence entity exists yet.',
        missing=['vendor_ack', 'acceptance_test_evidence'],
    )
    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='integration', entity_id=integration.id, link=link),
        projection=ProjectionSnapshot(lifecycle='enabled' if integration.enabled else 'disabled'),
        gate_results_by_action={action: [live_gate, evidence_gate]},
        hard_blocks={
            action: HardBlock(
                reason_code='LIVE_ACCEPTANCE_DOMAIN_NOT_IMPLEMENTED',
                reason='A durable tested/live-acceptance aggregate and evidence lineage must exist before this governed action can be enabled.',
                missing_requirements=('integration_acceptance_test', 'vendor_ack', 'acceptance_test_evidence'),
            )
        },
    )


def _asset_authorization_context(*, entity_id: str, link: TenantProject, actor_id: str) -> EntityCapabilityContext:
    decision = AssetAuthorization.objects.select_related('asset').filter(
        pk=entity_id,
        asset__project_id=link.project_id,
    ).first()
    if decision is None:
        raise EntityCapabilityNotFound('Entity capability target not found.')
    action = 'asset.authorization.approve'
    gate = _gate(
        GateType.AUTHORIZATION,
        GateState.BLOCKED,
        'AUTHORIZATION_REQUEST_ENTITY_NOT_IMPLEMENTED',
        'Existing AssetAuthorization rows are immutable decisions; the required submitted authorization-request entity does not exist yet.',
        missing=['asset_authorization_request'],
        evidence_refs=[str(decision.id)],
    )
    lifecycle = 'approved' if decision.authorized and decision.is_currently_valid else 'rejected'
    return EntityCapabilityContext(
        organization_id=str(link.organization_id),
        entity=_entity_ref(entity_type='asset_authorization', entity_id=decision.id, link=link),
        projection=ProjectionSnapshot(lifecycle=lifecycle),
        gate_results_by_action={action: [gate]},
        hard_blocks={
            action: HardBlock(
                reason_code='AUTHORIZATION_REQUEST_DOMAIN_NOT_IMPLEMENTED',
                reason='Approval cannot be projected from an immutable decision row; a submitted authorization-request aggregate must exist first.',
                missing_requirements=('asset_authorization_request',),
            )
        },
    )


_ADAPTERS: dict[str, Callable[..., EntityCapabilityContext]] = {
    'asset_authorization': _asset_authorization_context,
    'finding': _finding_context,
    'crown_jewel_objective': _objective_context,
    'campaign': _campaign_context,
    'detection_revision': _detection_context,
    'investigation_case': _investigation_context,
    'assurance_obligation': _assurance_context,
    'integration': _integration_context,
}


def supported_entity_types() -> list[str]:
    return sorted(_ADAPTERS)


def resolve_entity_capability_context(
    *,
    project_id: str,
    user_id: str,
    entity_type: str,
    entity_id: str,
) -> EntityCapabilityContext:
    link = _tenant_link_for_actor(project_id=str(project_id), user_id=str(user_id))
    normalized_type = str(entity_type or '').strip().lower()
    adapter = _ADAPTERS.get(normalized_type)
    if adapter is None:
        raise EntityCapabilityError(f'Unsupported AGOM entity type: {normalized_type or "<empty>"}.')
    return adapter(entity_id=str(entity_id), link=link, actor_id=str(user_id))


def build_entity_capability_manifest(
    *,
    project_id: str,
    user_id: str,
    entity_type: str,
    entity_id: str,
) -> AuthoritativeCapabilityManifest:
    context = resolve_entity_capability_context(
        project_id=project_id,
        user_id=user_id,
        entity_type=entity_type,
        entity_id=entity_id,
    )
    authority = resolve_actor_authority(
        organization_id=context.organization_id,
        user_id=user_id,
        project_id=context.entity.project_id,
        entity_type=context.entity.entity_type,
        entity_id=context.entity.entity_id,
    )
    responsibilities = set(authority.responsibilities)
    lifecycle = context.projection.lifecycle or ''
    contracts = [
        item for item in list_action_contracts()
        if item.entity_type == context.entity.entity_type
    ]
    capabilities: list[CapabilityItem] = []
    for contract in contracts:
        evaluated_layer = contract.actor_layers[0]
        item = evaluate_action(
            contract,
            current_state=lifecycle,
            actor_role=authority.role,
            actor_layer=evaluated_layer,
            actor_responsibilities=responsibilities,
            evidence_ready=(
                contract.action_id in context.evidence_ready_actions
                or not contract.evidence_requirements
            ),
            sod_eligible=(
                contract.action_id in context.sod_eligible_actions
                or not contract.sod_rules
            ),
            gate_results=context.gate_results_by_action.get(contract.action_id, []),
        ).model_copy(update={'evaluated_actor_layer': evaluated_layer})
        hard_block = context.hard_blocks.get(contract.action_id)
        if hard_block is not None and item.mode is not ActionMode.HIDDEN:
            item = CapabilityItem(
                action_id=contract.action_id,
                mode=ActionMode.BLOCKED,
                intent=contract.intent,
                evaluated_actor_layer=evaluated_layer,
                reason_code=hard_block.reason_code,
                reason=hard_block.reason,
                missing_requirements=list(hard_block.missing_requirements),
                gate_results=context.gate_results_by_action.get(contract.action_id, []),
            )
        capabilities.append(item)

    return AuthoritativeCapabilityManifest(
        evaluation_policy_version=POLICY_VERSION,
        entity=context.entity,
        projection=context.projection,
        actor_role=authority.role,
        actor_responsibilities=sorted(responsibilities),
        capabilities=capabilities,
        generated_at=datetime.now(timezone.utc),
    )
