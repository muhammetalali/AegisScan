from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from django.db import transaction

from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory


class RemediationState:
    NOT_REQUESTED = 'not_requested'
    REQUESTED = 'requested'
    VALIDATING = 'validating'
    NOT_FIXED = 'not_fixed'
    VALIDATION_PASSED = 'validation_passed'
    VERIFIED = 'verified'
    CLOSED = 'closed'
    FAILED = 'validation_failed'
    CANCELLED = 'cancelled'


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    RemediationState.NOT_REQUESTED: {RemediationState.REQUESTED},
    RemediationState.REQUESTED: {RemediationState.VALIDATING, RemediationState.CANCELLED, RemediationState.FAILED, RemediationState.VALIDATION_PASSED},
    RemediationState.VALIDATING: {RemediationState.NOT_FIXED, RemediationState.VALIDATION_PASSED, RemediationState.CANCELLED, RemediationState.FAILED},
    RemediationState.NOT_FIXED: {RemediationState.REQUESTED, RemediationState.VALIDATING},
    RemediationState.VALIDATION_PASSED: {RemediationState.VERIFIED, RemediationState.REQUESTED, RemediationState.VALIDATING},
    RemediationState.VERIFIED: {RemediationState.CLOSED, RemediationState.REQUESTED},
    RemediationState.CLOSED: {RemediationState.REQUESTED},
    RemediationState.FAILED: {RemediationState.REQUESTED},
    RemediationState.CANCELLED: {RemediationState.REQUESTED},
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_state(validation: Optional[ValidationRun]) -> str:
    if not validation:
        return RemediationState.NOT_REQUESTED
    result = validation.result if isinstance(validation.result, dict) else {}
    state = result.get('remediation_state')
    if state in _ALLOWED_TRANSITIONS:
        return state
    if validation.status == ValidationRun.Status.RUNNING:
        return RemediationState.VALIDATING
    if validation.status == ValidationRun.Status.FAILED:
        return RemediationState.FAILED
    if validation.status == ValidationRun.Status.CANCELLED:
        return RemediationState.CANCELLED
    if validation.status == ValidationRun.Status.COMPLETED:
        if result.get('finding_present') is False:
            return RemediationState.VALIDATION_PASSED
        if result.get('finding_present') is True:
            return RemediationState.NOT_FIXED
    return RemediationState.REQUESTED


def transition(
    validation_id: str | UUID,
    to_state: str,
    *,
    reason: str = '',
    evidence_id: str | None = None,
) -> ValidationRun:
    if to_state not in _ALLOWED_TRANSITIONS:
        raise ValueError(f'Unsupported remediation state: {to_state}')

    with transaction.atomic():
        validation = ValidationRun.objects.select_for_update().select_related('finding', 'user').get(pk=validation_id)
        finding = validation.finding
        if not finding:
            raise ValueError('Remediation transition requires a finding-linked validation run')
        finding = Vulnerability.objects.select_for_update().get(pk=finding.pk)

        current = get_state(validation)
        result: dict[str, Any] = dict(validation.result) if isinstance(validation.result, dict) else {}
        history = result.get('remediation_events')
        if not isinstance(history, list):
            history = []

        if current == to_state:
            if history:
                return validation
            current = RemediationState.NOT_REQUESTED
        if to_state not in _ALLOWED_TRANSITIONS.get(current, set()):
            raise ValueError(f'Invalid remediation transition: {current} -> {to_state}')

        now = _utc_now()
        history.append({
            'from': current,
            'to': to_state,
            'at': now,
            'reason': reason.strip(),
            'evidence_id': evidence_id,
            'user_id': str(validation.user_id),
        })
        result['remediation_state'] = to_state
        result['remediation_events'] = history
        validation.result = result
        validation.save(update_fields=['result'])

        old_status = finding.status
        if to_state in {
            RemediationState.REQUESTED,
            RemediationState.VALIDATING,
            RemediationState.NOT_FIXED,
            RemediationState.VALIDATION_PASSED,
            RemediationState.VERIFIED,
        } and finding.status == Vulnerability.Status.OPEN:
            finding.status = Vulnerability.Status.IN_PROGRESS
        elif to_state == RemediationState.CLOSED:
            finding.status = Vulnerability.Status.FIXED
            finding.fixed_at = datetime.now(timezone.utc)
            finding.fixed_by = validation.user

        if finding.status != old_status:
            finding.save(update_fields=['status', 'fixed_at', 'fixed_by', 'updated_at'])
            VulnerabilityStatusHistory.objects.create(
                vulnerability=finding,
                old_status=old_status,
                new_status=finding.status,
                changed_by=validation.user,
                reason=f'remediation_state={to_state}; {reason.strip()}'.strip(),
            )
        elif to_state == RemediationState.CLOSED:
            finding.save(update_fields=['fixed_at', 'fixed_by', 'updated_at'])

        return validation


def verify_validation(validation_id: str | UUID) -> ValidationRun:
    validation = ValidationRun.objects.select_related('finding', 'user').get(pk=validation_id)
    if validation.status != ValidationRun.Status.COMPLETED:
        raise ValueError('Fix verification requires a completed validation run')
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not False:
        raise ValueError('The validation still detects the finding; fix cannot be verified')
    evidence_id = result.get('evidence_id')
    if not evidence_id:
        raise ValueError('Completed validation has no linked validation evidence')
    if not Evidence.objects.filter(pk=evidence_id, finding=validation.finding).exists():
        raise ValueError('The linked validation evidence does not belong to this finding')

    current = get_state(validation)
    if current == RemediationState.REQUESTED:
        validation = transition(
            validation.id,
            RemediationState.VALIDATION_PASSED,
            reason='Completed authorized validation no longer detects the finding',
            evidence_id=str(evidence_id),
        )
    elif current not in {RemediationState.VALIDATION_PASSED, RemediationState.VERIFIED}:
        raise ValueError(f'Fix verification requires validation_passed state; current state is {current}')

    if get_state(validation) != RemediationState.VERIFIED:
        validation = transition(
            validation.id,
            RemediationState.VERIFIED,
            reason='Finding absence confirmed by completed authorized validation',
            evidence_id=str(evidence_id),
        )
    return validation
