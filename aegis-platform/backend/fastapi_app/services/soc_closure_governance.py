from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone as dt_timezone
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.evidence.models import Evidence, FindingDisposition, ValidationRun
from enterprise.models import InvestigationCase, OrganizationMembership
from enterprise.soc_models import InvestigationCaseState, InvestigationClosure
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state, transition as remediation_transition
from fastapi_app.services.security_operations import SecurityOperationsError, StaleCaseVersion, _append_event_locked, _membership, _sha

POLICY_VERSION = 'soc-closure.v1'
_CLOSURE_ROLES = {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN, OrganizationMembership.Role.MANAGER}


class ClosureGovernanceError(SecurityOperationsError):
    pass


@dataclass(frozen=True)
class ClosureResult:
    closure: InvestigationClosure
    state: InvestigationCaseState
    replayed: bool


def _latest_disposition(finding_id: str):
    return FindingDisposition.objects.filter(finding_id=finding_id).order_by('-created_at', '-id').first()


def _remediation_proof(*, finding_id: str, validation_id: str, project_id: str, state: InvestigationCaseState):
    if state.decision_action_id is None:
        raise ClosureGovernanceError('Remediated closure requires a linked DecisionAction response handoff.')
    validation = ValidationRun.objects.select_for_update().filter(pk=validation_id, finding_id=finding_id).first()
    if validation is None:
        raise ClosureGovernanceError('Validation run does not belong to the closure finding.')
    if str(validation.finding.project_id) != str(project_id):
        raise ClosureGovernanceError('Validation run is outside the investigation project scope.')
    if validation.status != ValidationRun.Status.COMPLETED:
        raise ClosureGovernanceError('Remediated closure requires a completed validation run.')
    if get_state(validation) != RemediationState.VERIFIED:
        raise ClosureGovernanceError('Remediated closure requires remediation state VERIFIED.')
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not False:
        raise ClosureGovernanceError('Verified remediation proof must show finding_present=false.')
    evidence_id = result.get('evidence_id')
    evidence = Evidence.objects.filter(pk=evidence_id, finding_id=finding_id).first() if evidence_id else None
    if evidence is None:
        raise ClosureGovernanceError('Verified remediation proof requires finding-linked validation evidence.')
    source_sha = _sha({'validation_id': str(validation.id), 'validation_status': validation.status, 'remediation_state': get_state(validation), 'finding_present': result.get('finding_present'), 'evidence_id': str(evidence.id), 'evidence_sha256': evidence.sha256, 'authorization_decision_id': str(validation.authorization_decision_id or '')})
    return validation, evidence, source_sha


def _disposition_proof(*, finding_id: str, disposition_id: str, closure_type: str, organization_id: str):
    disposition = FindingDisposition.objects.select_for_update().filter(pk=disposition_id, finding_id=finding_id).first()
    if disposition is None:
        raise ClosureGovernanceError('Governed disposition does not belong to the closure finding.')
    if str(disposition.organization_id) != str(organization_id):
        raise ClosureGovernanceError('Governed disposition is outside the investigation tenant.')
    if disposition.disposition != closure_type:
        raise ClosureGovernanceError('Closure type does not match the governed finding disposition.')
    latest = _latest_disposition(finding_id)
    if latest is None or latest.id != disposition.id:
        raise ClosureGovernanceError('Closure requires the latest immutable finding disposition.')
    if closure_type in {FindingDisposition.Disposition.ACCEPTED_RISK, FindingDisposition.Disposition.WONT_FIX} and (disposition.review_at is None or disposition.review_at <= timezone.now()):
        raise ClosureGovernanceError('Risk disposition is expired and cannot authorize closure.')
    source_sha = _sha({'disposition_id': str(disposition.id), 'disposition': disposition.disposition, 'policy_version': disposition.policy_version, 'request_fingerprint': disposition.request_fingerprint, 'risk_correlation_sha256': disposition.risk_correlation_sha256, 'review_at': disposition.review_at.isoformat() if disposition.review_at else '', 'duplicate_of_id': str(disposition.duplicate_of_id or '')})
    return disposition, source_sha


def _existing_replay_matches(existing: InvestigationClosure, *, finding_id: str, closure_type: str, validation_id: str | None, disposition_id: str | None, rationale: str) -> bool:
    return (
        str(existing.finding_id) == str(finding_id)
        and existing.closure_type == closure_type
        and str(existing.validation_run_id or '') == str(validation_id or '')
        and str(existing.disposition_id or '') == str(disposition_id or '')
        and existing.rationale == rationale
    )


def close_investigation_case(*, case_id: str, project_id: str, user_id: str, expected_version: int, finding_id: str, closure_type: str, rationale: str = '', validation_id: str | None = None, disposition_id: str | None = None) -> ClosureResult:
    link, _ = _membership(project_id, user_id, _CLOSURE_ROLES)
    allowed = {value for value, _label in InvestigationClosure.ClosureType.choices}
    if closure_type not in allowed:
        raise ClosureGovernanceError('Unsupported investigation closure type.')
    normalized_rationale = ' '.join((rationale or '').strip().split())
    if closure_type == InvestigationClosure.ClosureType.REMEDIATED:
        if not validation_id or disposition_id:
            raise ClosureGovernanceError('Remediated closure requires validation_id only.')
    elif not disposition_id or validation_id:
        raise ClosureGovernanceError('Disposition closure requires disposition_id only.')

    with transaction.atomic():
        state = InvestigationCaseState.objects.select_for_update().select_related('case', 'decision_action').filter(case_id=case_id, case__project_id=project_id).first()
        if state is None:
            raise ClosureGovernanceError('SOC-managed investigation case not found in project.')
        case = state.case
        if not case.findings.filter(pk=finding_id).exists():
            raise ClosureGovernanceError('Closure finding is not linked to this investigation case.')

        existing = InvestigationClosure.objects.filter(case_id=case_id).first()
        if existing is not None:
            if _existing_replay_matches(existing, finding_id=finding_id, closure_type=closure_type, validation_id=validation_id, disposition_id=disposition_id, rationale=normalized_rationale):
                return ClosureResult(existing, state, True)
            raise ClosureGovernanceError('Investigation case is already closed with different immutable semantics.')
        if state.version != expected_version:
            raise StaleCaseVersion(f'Expected case version {expected_version}, current version is {state.version}.')
        if case.status not in {InvestigationCase.Status.INVESTIGATING, InvestigationCase.Status.DECIDED}:
            raise ClosureGovernanceError('Investigation must be investigating or decided before governed closure.')

        validation = evidence = disposition = None
        if closure_type == InvestigationClosure.ClosureType.REMEDIATED:
            validation, evidence, source_sha = _remediation_proof(finding_id=finding_id, validation_id=validation_id, project_id=project_id, state=state)
            source_id = str(validation.id)
        else:
            disposition, source_sha = _disposition_proof(finding_id=finding_id, disposition_id=disposition_id, closure_type=closure_type, organization_id=str(link.organization_id))
            source_id = str(disposition.id)

        fingerprint = _sha({'case_id': str(case_id), 'generation': state.generation, 'finding_id': str(finding_id), 'closure_type': closure_type, 'source_id': source_id, 'source_sha256': source_sha, 'decision_action_id': str(state.decision_action_id or ''), 'policy_version': POLICY_VERSION, 'rationale': normalized_rationale})
        if validation is not None:
            remediation_transition(validation.id, RemediationState.CLOSED, reason=f'Governed SOC investigation closure {case.id}; {normalized_rationale}'.strip(), evidence_id=str(evidence.id))

        closure = InvestigationClosure.objects.create(case=case, finding_id=finding_id, closure_type=closure_type, validation_run=validation, disposition=disposition, evidence=evidence, decision_action=state.decision_action, policy_version=POLICY_VERSION, source_sha256=source_sha, closure_fingerprint=fingerprint, rationale=normalized_rationale, closed_by_id=user_id)
        old_status = case.status
        case.status = InvestigationCase.Status.CLOSED
        case.closed_at = timezone.now()
        case.save(update_fields=['status', 'closed_at', 'updated_at'])
        state.version += 1
        state.save(update_fields=['version', 'updated_at'])
        _append_event_locked(case, user_id, 'case.closed.governed', {'closure_id': str(closure.id), 'closure_type': closure_type, 'finding_id': str(finding_id), 'source_id': source_id, 'source_sha256': source_sha, 'closure_fingerprint': fingerprint, 'policy_version': POLICY_VERSION, 'old_status': old_status, 'new_status': InvestigationCase.Status.CLOSED, 'version': state.version})
        return ClosureResult(closure, state, False)


def get_investigation_closure(*, case_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, set(OrganizationMembership.Role.values))
    closure = InvestigationClosure.objects.select_related('case', 'validation_run', 'disposition', 'evidence', 'decision_action').filter(case_id=case_id, case__project_id=project_id).first()
    if closure is None:
        raise ClosureGovernanceError('Governed investigation closure not found.')
    return {'closure_id': str(closure.id), 'case_id': str(closure.case_id), 'finding_id': str(closure.finding_id), 'closure_type': closure.closure_type, 'validation_id': str(closure.validation_run_id) if closure.validation_run_id else None, 'disposition_id': str(closure.disposition_id) if closure.disposition_id else None, 'evidence_id': str(closure.evidence_id) if closure.evidence_id else None, 'decision_action_id': closure.decision_action_id, 'source_sha256': closure.source_sha256, 'closure_fingerprint': closure.closure_fingerprint, 'policy_version': closure.policy_version, 'closed_by': str(closure.closed_by_id), 'closed_at': closure.closed_at.astimezone(dt_timezone.utc).isoformat()}
