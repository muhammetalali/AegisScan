from __future__ import annotations

from datetime import datetime, timezone

from django.db import close_old_connections, transaction

from django_project.audit.models import AuditLog
from django_project.evidence.models import ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from fastapi_app.tasks.nmap_finding_validation import validate_nmap_finding_e2e


def _now():
    return datetime.now(timezone.utc)


def _serialize(validation: ValidationRun) -> dict:
    result = dict(validation.result or {})
    result.setdefault('remediation_id', f'rem-{validation.id}')
    result.setdefault('finding_id', str(validation.finding_id) if validation.finding_id else None)
    result.setdefault('validation_id', str(validation.id))
    result.setdefault('actor', str(validation.user_id))
    result.setdefault('action_type', 'validated_closure')
    result.setdefault('created_at', validation.created_at.isoformat())
    result['completed_at'] = validation.completed_at.isoformat() if validation.completed_at else None
    return result


def get_run(remediation_id: str) -> dict | None:
    validation_id = remediation_id.removeprefix('rem-')
    try:
        validation = ValidationRun.objects.get(pk=validation_id)
    except (ValidationRun.DoesNotExist, ValueError):
        return None
    return _serialize(validation)


def list_runs_for_finding(finding_id: str) -> list[dict]:
    return [
        _serialize(item)
        for item in ValidationRun.objects.filter(
            finding_id=finding_id,
            result__remediation_id__isnull=False,
        ).order_by('-created_at')
    ]


def _persist_run(validation: ValidationRun, *, remediation_id: str, state: str, risk_before: float,
                 risk_after: float | None, risk_delta: float | None, evidence_id: str | None,
                 reason: str, completed_at):
    validation.result = {
        **(validation.result or {}),
        'remediation_id': remediation_id,
        'finding_id': str(validation.finding_id) if validation.finding_id else None,
        'validation_id': str(validation.id),
        'actor': str(validation.user_id),
        'action_type': 'validated_closure',
        'state': state,
        'risk_before': risk_before,
        'risk_after': risk_after,
        'risk_delta': risk_delta,
        'evidence_id': evidence_id,
        'reason': reason,
        'created_at': validation.created_at.isoformat(),
        'completed_at': completed_at.isoformat() if completed_at else None,
    }
    validation.save(update_fields=['result'])
    return _serialize(validation)


def _persist_verified_closure(validation: ValidationRun, finding_id: str, actor_id: str,
                              reason: str, risk_before: float, remediation_id: str,
                              evidence_id: str | None, completed_at):
    with transaction.atomic():
        locked = Vulnerability.objects.select_for_update(of=('self',)).get(pk=finding_id)
        old_status = locked.status
        locked.status = Vulnerability.Status.FIXED
        locked.fixed_at = completed_at
        locked.fixed_by_id = actor_id
        locked.validation_status = 'verified'
        locked.risk_score = 0
        locked.save(update_fields=['status', 'fixed_at', 'fixed_by', 'validation_status', 'risk_score', 'updated_at'])
        history = VulnerabilityStatusHistory.objects.filter(
            vulnerability_id=locked.id,
            old_status=old_status,
            new_status=Vulnerability.Status.FIXED,
            changed_by_id=actor_id,
        ).first()
        if history is None:
            history = VulnerabilityStatusHistory.objects.create(
                vulnerability_id=locked.id,
                old_status=old_status,
                new_status=Vulnerability.Status.FIXED,
                changed_by_id=actor_id,
                reason=reason,
            )
        elif history.reason != reason:
            history.reason = reason
            history.save(update_fields=['reason'])
        AuditLog.objects.create(
            user_id=actor_id,
            action=AuditLog.Action.VULN_FIX_VERIFY,
            result=AuditLog.Result.SUCCESS,
            resource_type='vulnerability',
            resource_id=str(locked.id),
            resource_repr=locked.title[:200],
            changes={'status': [old_status, Vulnerability.Status.FIXED], 'risk_score': [risk_before, 0]},
            metadata={
                'validation_id': str(validation.id),
                'evidence_id': evidence_id,
                'remediation_id': remediation_id,
                'status_history_id': str(history.id),
            },
            ip_address='127.0.0.1',
            request_id=validation.id,
        )
        validation.result = {
            **(validation.result or {}),
            'remediation_id': remediation_id,
            'state': 'verified',
            'risk_before': risk_before,
            'risk_after': 0.0,
            'risk_delta': -risk_before,
            'evidence_id': evidence_id,
            'reason': reason,
            'status_history_id': str(history.id),
            'created_at': validation.created_at.isoformat(),
            'completed_at': completed_at.isoformat(),
        }
        validation.save(update_fields=['result'])
    return history.id


def _ensure_history_committed(*, finding_id: str, old_status: str, actor_id: str, reason: str) -> str:
    close_old_connections()
    try:
        history = VulnerabilityStatusHistory.objects.filter(
            vulnerability_id=finding_id,
            old_status=old_status,
            new_status=Vulnerability.Status.FIXED,
            changed_by_id=actor_id,
        ).order_by('-created_at', '-id').first()
        if history is not None:
            return str(history.id)
        with transaction.atomic():
            history = VulnerabilityStatusHistory.objects.create(
                vulnerability_id=finding_id,
                old_status=old_status,
                new_status=Vulnerability.Status.FIXED,
                changed_by_id=actor_id,
                reason=reason,
            )
        if not VulnerabilityStatusHistory.objects.filter(pk=history.pk).exists():
            raise RuntimeError('Verified closure status history was not committed')
        return str(history.id)
    finally:
        close_old_connections()


def execute_validated_closure(finding_id: str, actor_id: str, reason: str) -> dict:
    with transaction.atomic():
        finding = (
            Vulnerability.objects.select_for_update(of=('self',))
            .select_related('asset', 'scan')
            .filter(pk=finding_id)
            .first()
        )
        if not finding:
            raise ValueError('Finding not found')
        if finding.status == Vulnerability.Status.FIXED:
            raise ValueError('Finding is already fixed')
        if not finding.asset_id or not finding.scan_id:
            raise ValueError('Finding must retain asset and originating scan lineage')
        if (finding.source_engine or '').strip().lower() != 'nmap':
            raise ValueError('Validated closure currently supports only Nmap findings')
        authorization_id = finding.scan.authorization_decision_id
        if not authorization_id:
            raise ValueError('Finding is not bound to an authorization decision')
        target = finding.scan.config.get('target', '') if isinstance(finding.scan.config, dict) else ''
        validation = ValidationRun.objects.create(
            user_id=actor_id,
            finding=finding,
            finding_identity_snapshot=finding.id,
            authorization_decision_id=authorization_id,
            target_type='ip',
            target_value=target,
            scope=target,
            profile='quick',
            engines=['nmap'],
            authorized=True,
        )

    close_old_connections()
    try:
        result = validate_nmap_finding_e2e.run(str(validation.id))
    finally:
        close_old_connections()

    validation.refresh_from_db()
    finding.refresh_from_db()

    remediation_id = f'rem-{validation.id}'
    risk_before = float(finding.risk_score or 0)
    completed_at = validation.completed_at or _now()
    evidence_id = result.get('evidence_id') if isinstance(result, dict) else None

    if not isinstance(result, dict) or result.get('finding_present') is not False or validation.status != ValidationRun.Status.COMPLETED:
        return _persist_run(
            validation,
            remediation_id=remediation_id,
            state='rejected_by_revalidation',
            risk_before=risk_before,
            risk_after=risk_before,
            risk_delta=0.0,
            evidence_id=evidence_id,
            reason=reason,
            completed_at=completed_at,
        )

    old_status = finding.status
    history_id = _persist_verified_closure(
        validation, str(finding.id), actor_id, reason, risk_before, remediation_id, evidence_id, completed_at,
    )
    committed_history_id = _ensure_history_committed(
        finding_id=str(finding.id), old_status=old_status, actor_id=actor_id, reason=reason,
    )

    close_old_connections()
    try:
        validation.refresh_from_db()
    finally:
        close_old_connections()
    if committed_history_id != str(history_id):
        validation.result = {**(validation.result or {}), 'status_history_id': committed_history_id}
        validation.save(update_fields=['result'])
        validation.refresh_from_db()

    finding.refresh_from_db()
    close_old_connections()
    return _serialize(validation)
