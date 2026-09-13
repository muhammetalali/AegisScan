from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.db import transaction
from django.utils import timezone

from enterprise.detection_models import DetectionRevision, DetectionValidation
from enterprise.models import DecisionAction, InvestigationCase, OrganizationMembership, TenantProject
from enterprise.soc_models import InvestigationAuditEvent, InvestigationCaseState, InvestigationSignalLink, SecuritySignal
from fastapi_app.services.detection_engineering import _matches


_AUTHOR_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
    OrganizationMembership.Role.ANALYST,
}
_TRANSITIONS = {
    InvestigationCase.Status.OPEN: {InvestigationCase.Status.INVESTIGATING},
    InvestigationCase.Status.INVESTIGATING: {InvestigationCase.Status.DECIDED, InvestigationCase.Status.CLOSED},
    InvestigationCase.Status.DECIDED: {InvestigationCase.Status.INVESTIGATING, InvestigationCase.Status.CLOSED},
    InvestigationCase.Status.CLOSED: set(),
}


class SecurityOperationsError(ValueError):
    pass


class StaleCaseVersion(SecurityOperationsError):
    pass


@dataclass(frozen=True)
class SignalResult:
    signal: SecuritySignal
    case: InvestigationCase
    state: InvestigationCaseState
    replayed: bool
    case_created: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _membership(project_id: str, user_id: str, roles: set[str] = _AUTHOR_ROLES):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None:
        raise SecurityOperationsError('Project is not bound to an enterprise tenant.')
    membership = OrganizationMembership.objects.filter(
        organization=link.organization, user_id=user_id, is_active=True, user__is_active=True, role__in=roles,
    ).first()
    if membership is None:
        raise PermissionError('Active tenant role does not permit this security operations mutation.')
    return link, membership


def _append_event_locked(case: InvestigationCase, actor_id: str, event_type: str, payload: dict[str, Any]):
    previous = InvestigationAuditEvent.objects.filter(case=case).order_by('-id').first()
    previous_hash = previous.entry_hash if previous else ''
    envelope = {
        'case_id': str(case.id),
        'actor_id': str(actor_id),
        'event_type': event_type,
        'payload': payload,
        'previous_hash': previous_hash,
    }
    return InvestigationAuditEvent.objects.create(
        case=case, actor_id=actor_id, event_type=event_type, payload=payload,
        previous_hash=previous_hash, entry_hash=_sha(envelope),
    )


def _serialize_state(state: InvestigationCaseState) -> dict[str, Any]:
    return {
        'case_id': str(state.case_id),
        'status': state.case.status,
        'version': state.version,
        'generation': state.generation,
        'base_correlation_key': state.base_correlation_key,
        'decision_action_id': state.decision_action_id,
    }


def ingest_detection_signal(*, revision_id: str, project_id: str, user_id: str, event: dict[str, Any], observed_at: datetime, source: str = 'siem') -> SignalResult:
    if not isinstance(event, dict) or not event:
        raise SecurityOperationsError('event must be a non-empty object.')
    if source not in {'siem', 'edr', 'replay', 'sensor'}:
        raise SecurityOperationsError('source must be siem, edr, replay, or sensor.')
    if observed_at.tzinfo is None:
        raise SecurityOperationsError('observed_at must be timezone-aware.')
    link, _ = _membership(project_id, user_id)
    with transaction.atomic():
        # Project lock serializes first-case correlation and generation allocation.
        TenantProject.objects.select_for_update().get(pk=link.pk)
        # Lock only the revision row. source_evidence is nullable and therefore
        # select_related() uses an OUTER JOIN; PostgreSQL rejects FOR UPDATE on
        # the nullable side unless the locked relation is scoped explicitly.
        revision = (
            DetectionRevision.objects.select_for_update(of=('self',)).select_related('rule', 'source_finding', 'source_evidence')
            .filter(pk=revision_id, rule__project_id=project_id).first()
        )
        if revision is None:
            raise SecurityOperationsError('Detection revision not found in project.')
        latest = revision.rule.revisions.order_by('-version').first()
        if latest is None or latest.id != revision.id:
            raise SecurityOperationsError('Only the latest detection revision may emit operational signals.')
        validation = revision.validations.filter(status=DetectionValidation.Status.PASSED).order_by('-created_at').first()
        if validation is None:
            raise SecurityOperationsError('A passed detection validation is required before signal ingestion.')
        if not _matches(event, revision.spec):
            raise SecurityOperationsError('Telemetry event does not satisfy the governed detection revision.')

        payload_sha = _sha(event)
        fingerprint = _sha({
            'revision_id': str(revision.id), 'validation_id': str(validation.id), 'source': source,
            'observed_at': observed_at.astimezone(dt_timezone.utc).isoformat(), 'payload_sha256': payload_sha,
        })
        existing = SecuritySignal.objects.filter(fingerprint=fingerprint).first()
        if existing:
            case_link = InvestigationSignalLink.objects.select_related('case__soc_state').get(signal=existing)
            return SignalResult(existing, case_link.case, case_link.case.soc_state, True, False)

        signal = SecuritySignal.objects.create(
            organization=link.organization, project_id=project_id, validation=validation, revision=revision,
            finding=revision.source_finding, fingerprint=fingerprint, severity=revision.spec['severity'],
            attack_techniques=revision.attack_techniques, payload_sha256=payload_sha,
            observed_at=observed_at, created_by_id=user_id,
        )
        base_key = _sha({
            'project_id': str(project_id), 'rule_id': str(revision.rule_id),
            'finding_id': str(revision.source_finding_id), 'attack_techniques': sorted(revision.attack_techniques),
        })
        latest_state = (
            InvestigationCaseState.objects.select_for_update().select_related('case')
            .filter(base_correlation_key=base_key).order_by('-generation').first()
        )
        case_created = latest_state is None or latest_state.case.status == InvestigationCase.Status.CLOSED
        if case_created:
            generation = 1 if latest_state is None else latest_state.generation + 1
            case = InvestigationCase.objects.create(
                organization=link.organization, project_id=project_id, owner_id=user_id,
                title=f'Detection: {revision.rule.title}',
                description=f'Correlated operational signals for governed detection rule {revision.rule.slug}.',
            )
            case.findings.add(revision.source_finding)
            if revision.source_evidence_id:
                case.evidence.add(revision.source_evidence)
            state = InvestigationCaseState.objects.create(
                case=case, base_correlation_key=base_key, generation=generation, version=1,
            )
            _append_event_locked(case, user_id, 'case.created', {
                'generation': generation, 'base_correlation_key': base_key,
                'detection_rule_id': str(revision.rule_id), 'detection_revision_id': str(revision.id),
                'source_finding_id': str(revision.source_finding_id),
            })
        else:
            state = latest_state
            case = state.case
            case.findings.add(revision.source_finding)
            if revision.source_evidence_id:
                case.evidence.add(revision.source_evidence)

        InvestigationSignalLink.objects.create(case=case, signal=signal, linked_by_id=user_id)
        _append_event_locked(case, user_id, 'signal.correlated', {
            'signal_id': str(signal.id), 'fingerprint': signal.fingerprint, 'payload_sha256': payload_sha,
            'source': source, 'severity': signal.severity, 'attack_techniques': signal.attack_techniques,
            'validation_id': str(validation.id), 'revision_id': str(revision.id),
        })
        return SignalResult(signal, case, state, False, case_created)


def transition_case(*, case_id: str, project_id: str, user_id: str, expected_version: int, status: str, decision_summary: str = '') -> InvestigationCaseState:
    _membership(project_id, user_id)
    valid_statuses = {value for value, _ in InvestigationCase.Status.choices}
    if status not in valid_statuses:
        raise SecurityOperationsError('Invalid investigation case status.')
    with transaction.atomic():
        state = (
            InvestigationCaseState.objects.select_for_update().select_related('case')
            .filter(case_id=case_id, case__project_id=project_id).first()
        )
        if state is None:
            raise SecurityOperationsError('SOC-managed investigation case not found in project.')
        if state.version != expected_version:
            raise StaleCaseVersion(f'Expected case version {expected_version}, current version is {state.version}.')
        case = state.case
        if status not in _TRANSITIONS.get(case.status, set()):
            raise SecurityOperationsError(f'Invalid case transition: {case.status} -> {status}.')
        old_status = case.status
        case.status = status
        if decision_summary:
            case.decision_summary = decision_summary
        case.closed_at = timezone.now() if status == InvestigationCase.Status.CLOSED else None
        case.save(update_fields=['status', 'decision_summary', 'closed_at', 'updated_at'])
        state.version += 1
        state.save(update_fields=['version', 'updated_at'])
        _append_event_locked(case, user_id, 'case.transitioned', {
            'old_status': old_status, 'new_status': status, 'version': state.version,
            'decision_summary_sha256': _sha(decision_summary) if decision_summary else '',
        })
        return state


def attach_decision_action(*, case_id: str, action_id: str, project_id: str, user_id: str, expected_version: int) -> tuple[InvestigationCaseState, bool]:
    link, _ = _membership(project_id, user_id, {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN, OrganizationMembership.Role.MANAGER})
    with transaction.atomic():
        state = (
            InvestigationCaseState.objects.select_for_update().select_related('case')
            .filter(case_id=case_id, case__project_id=project_id).first()
        )
        if state is None:
            raise SecurityOperationsError('SOC-managed investigation case not found in project.')
        if state.version != expected_version:
            raise StaleCaseVersion(f'Expected case version {expected_version}, current version is {state.version}.')
        action = DecisionAction.objects.filter(action_id=action_id, project_id=project_id, organization=link.organization).first()
        if action is None:
            raise SecurityOperationsError('Decision action is outside the investigation tenant/project scope.')
        if state.decision_action_id:
            if state.decision_action_id == action.action_id:
                return state, True
            raise SecurityOperationsError('Investigation case already has a different response action.')
        state.decision_action = action
        state.version += 1
        state.save(update_fields=['decision_action', 'version', 'updated_at'])
        _append_event_locked(state.case, user_id, 'response.handoff', {
            'decision_action_id': action.action_id, 'action_state': action.state, 'version': state.version,
        })
        return state, False


def verify_case_chain(*, case_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, set(OrganizationMembership.Role.values))
    case = InvestigationCase.objects.filter(pk=case_id, project_id=project_id).first()
    if case is None:
        raise SecurityOperationsError('Investigation case not found in project.')
    previous = ''
    rows = list(InvestigationAuditEvent.objects.filter(case=case).order_by('id'))
    for row in rows:
        if row.previous_hash != previous:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'previous_hash'}
        envelope = {
            'case_id': str(case.id), 'actor_id': str(row.actor_id), 'event_type': row.event_type,
            'payload': row.payload, 'previous_hash': row.previous_hash,
        }
        expected = _sha(envelope)
        if row.entry_hash != expected:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'entry_hash'}
        previous = row.entry_hash
    return {'valid': True, 'entries': len(rows), 'head': previous}


def get_case_state(*, case_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, set(OrganizationMembership.Role.values))
    state = InvestigationCaseState.objects.select_related('case', 'decision_action').filter(case_id=case_id, case__project_id=project_id).first()
    if state is None:
        raise SecurityOperationsError('SOC-managed investigation case not found in project.')
    data = _serialize_state(state)
    data['signal_count'] = InvestigationSignalLink.objects.filter(case_id=case_id).count()
    data['event_count'] = InvestigationAuditEvent.objects.filter(case_id=case_id).count()
    return data
