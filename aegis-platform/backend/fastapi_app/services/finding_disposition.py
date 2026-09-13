from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from django.db import IntegrityError, transaction

from django_project.audit.models import AuditLog
from django_project.evidence.models import FindingDisposition
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from enterprise.models import OrganizationMembership, RiskCorrelationSnapshot, TenantProject

from .audit_writer import add_audit_entry


POLICY_VERSION = 'finding-disposition.v1'
MAX_REVIEW_DAYS = 365
RISK_GOVERNANCE_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
}
TRIAGE_ROLES = RISK_GOVERNANCE_ROLES | {OrganizationMembership.Role.ANALYST}


class FindingDispositionError(ValueError):
    pass


@dataclass(frozen=True)
class DispositionResult:
    disposition: FindingDisposition
    replayed: bool
    status_changed: bool
    previous_status: str


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _normalize_rationale(value: str) -> str:
    return ' '.join(str(value or '').strip().split())


def _resolve_tenant_membership(*, project_id: UUID | str, actor_id: UUID | str, disposition: str):
    tenant_link = TenantProject.objects.select_related('organization').filter(project_id=project_id).first()
    if tenant_link is None or not tenant_link.organization.is_active:
        raise FindingDispositionError('Finding project is not linked to an active tenant organization.')
    membership = OrganizationMembership.objects.filter(
        organization=tenant_link.organization,
        user_id=actor_id,
        is_active=True,
    ).first()
    if membership is None:
        raise FindingDispositionError('Actor has no active membership in the finding tenant.')
    allowed = TRIAGE_ROLES if disposition == FindingDisposition.Disposition.DUPLICATE else RISK_GOVERNANCE_ROLES
    if membership.role not in allowed:
        raise FindingDispositionError(f'Role {membership.role} is not authorized for {disposition}.')
    return tenant_link.organization, membership


def _validate_transition(current: str, target: str) -> None:
    allowed = {
        Vulnerability.Status.OPEN: {
            Vulnerability.Status.ACCEPTED_RISK, Vulnerability.Status.WONT_FIX, Vulnerability.Status.DUPLICATE,
        },
        Vulnerability.Status.CONFIRMED: {
            Vulnerability.Status.ACCEPTED_RISK, Vulnerability.Status.WONT_FIX, Vulnerability.Status.DUPLICATE,
        },
        Vulnerability.Status.ACCEPTED_RISK: {Vulnerability.Status.WONT_FIX},
        Vulnerability.Status.WONT_FIX: {Vulnerability.Status.ACCEPTED_RISK},
    }
    if current == target:
        return
    if target not in allowed.get(current, set()):
        raise FindingDispositionError(f'Finding status {current} cannot transition to {target} through disposition governance.')


def _resolve_latest_risk(*, finding: Vulnerability, risk_correlation_id: UUID | str) -> RiskCorrelationSnapshot:
    risk = RiskCorrelationSnapshot.objects.select_for_update().filter(pk=risk_correlation_id).first()
    if risk is None:
        raise FindingDispositionError('Risk correlation snapshot was not found.')
    if risk.project_id != finding.project_id or risk.vulnerability_id != finding.id:
        raise FindingDispositionError('Risk correlation snapshot does not belong to this finding and project.')
    latest = RiskCorrelationSnapshot.objects.filter(vulnerability=finding).order_by('-created_at', '-id').first()
    if latest is None or latest.id != risk.id:
        raise FindingDispositionError('Risk acceptance requires the latest immutable risk correlation snapshot.')
    return risk


def _validate_review_at(review_at: datetime | None) -> datetime:
    if review_at is None:
        raise FindingDispositionError('Risk dispositions require review_at.')
    if review_at.tzinfo is None:
        review_at = review_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if review_at <= now:
        raise FindingDispositionError('review_at must be in the future.')
    if review_at > now + timedelta(days=MAX_REVIEW_DAYS):
        raise FindingDispositionError(f'review_at cannot exceed {MAX_REVIEW_DAYS} days.')
    return review_at


def _canonical_duplicate(*, finding: Vulnerability, duplicate_of_id: UUID | str) -> Vulnerability:
    target = Vulnerability.objects.select_for_update().filter(pk=duplicate_of_id).first()
    if target is None:
        raise FindingDispositionError('Duplicate target was not found.')
    if target.id == finding.id:
        raise FindingDispositionError('A finding cannot be a duplicate of itself.')
    if target.project_id != finding.project_id:
        raise FindingDispositionError('Duplicate target must belong to the same project.')

    seen = {str(finding.id)}
    current = target
    while current.status == Vulnerability.Status.DUPLICATE and current.duplicate_of_id:
        if str(current.id) in seen:
            raise FindingDispositionError('Duplicate chain would create or traverse a cycle.')
        seen.add(str(current.id))
        current = Vulnerability.objects.select_for_update().get(pk=current.duplicate_of_id)
        if current.project_id != finding.project_id:
            raise FindingDispositionError('Duplicate chain crosses project boundaries.')
    if str(current.id) in seen:
        raise FindingDispositionError('Duplicate chain would create a cycle.')
    if current.status in {Vulnerability.Status.FIXED, Vulnerability.Status.FALSE_POSITIVE}:
        raise FindingDispositionError('Duplicate target must resolve to an active governed finding.')
    return current


def _request_fingerprint(*, actor_id, finding_id, organization_id, disposition, rationale, risk_id, review_at, duplicate_id) -> str:
    return _canonical_digest({
        'actor_id': str(actor_id),
        'finding_id': str(finding_id),
        'organization_id': str(organization_id),
        'disposition': disposition,
        'rationale': _normalize_rationale(rationale),
        'risk_correlation_id': str(risk_id or ''),
        'review_at': review_at.isoformat() if review_at else '',
        'duplicate_of_id': str(duplicate_id or ''),
        'policy_version': POLICY_VERSION,
    })


def govern_finding_disposition(
    *, finding_id: UUID | str, disposition: str, rationale: str, actor_id: UUID | str,
    risk_correlation_id: UUID | str | None = None, review_at: datetime | None = None,
    duplicate_of_id: UUID | str | None = None,
) -> DispositionResult:
    normalized = _normalize_rationale(rationale)
    if len(normalized) < 3:
        raise FindingDispositionError('A rationale of at least 3 characters is required.')
    if disposition not in FindingDisposition.Disposition.values:
        raise FindingDispositionError(f'Unsupported finding disposition: {disposition}')

    with transaction.atomic():
        finding = Vulnerability.objects.select_for_update().get(pk=finding_id)
        organization, membership = _resolve_tenant_membership(
            project_id=finding.project_id, actor_id=actor_id, disposition=disposition,
        )
        target_status = disposition
        _validate_transition(finding.status, target_status)

        risk = None
        canonical_duplicate = None
        normalized_review = None
        risk_hash = ''
        if disposition in {FindingDisposition.Disposition.ACCEPTED_RISK, FindingDisposition.Disposition.WONT_FIX}:
            if duplicate_of_id is not None:
                raise FindingDispositionError('Risk dispositions cannot include duplicate_of_id.')
            normalized_review = _validate_review_at(review_at)
            if risk_correlation_id is None:
                raise FindingDispositionError('Risk dispositions require risk_correlation_id.')
            risk = _resolve_latest_risk(finding=finding, risk_correlation_id=risk_correlation_id)
            risk_hash = _canonical_digest({
                'id': str(risk.id), 'correlation_sha256': risk.correlation_sha256,
                'score': risk.score, 'priority': risk.priority, 'source_snapshot_sha256': risk.source_snapshot_sha256,
            })
        else:
            if risk_correlation_id is not None or review_at is not None:
                raise FindingDispositionError('Duplicate disposition cannot include risk correlation or review_at.')
            if duplicate_of_id is None:
                raise FindingDispositionError('Duplicate disposition requires duplicate_of_id.')
            canonical_duplicate = _canonical_duplicate(finding=finding, duplicate_of_id=duplicate_of_id)

        fingerprint = _request_fingerprint(
            actor_id=actor_id, finding_id=finding.id, organization_id=organization.id,
            disposition=disposition, rationale=normalized, risk_id=risk.id if risk else None,
            review_at=normalized_review, duplicate_id=canonical_duplicate.id if canonical_duplicate else None,
        )
        existing = FindingDisposition.objects.select_for_update().filter(request_fingerprint=fingerprint).first()
        if existing is not None:
            return DispositionResult(existing, True, False, finding.status)
        if finding.status == target_status:
            raise FindingDispositionError('Finding already has this disposition with different immutable semantics.')

        previous_status = finding.status
        try:
            record = FindingDisposition.objects.create(
                finding=finding, disposition=disposition, organization=organization,
                risk_correlation=risk, duplicate_of=canonical_duplicate, created_by_id=actor_id,
                approving_role=membership.role, policy_version=POLICY_VERSION,
                risk_correlation_sha256=risk_hash, request_fingerprint=fingerprint,
                rationale=normalized, review_at=normalized_review,
                metadata={
                    'risk_score': risk.score if risk else None,
                    'risk_priority': risk.priority if risk else None,
                    'risk_correlation_sha256': risk.correlation_sha256 if risk else None,
                    'canonical_duplicate_of_id': str(canonical_duplicate.id) if canonical_duplicate else None,
                },
            )
        except IntegrityError:
            existing = FindingDisposition.objects.filter(request_fingerprint=fingerprint).first()
            if existing is None:
                raise
            return DispositionResult(existing, True, False, finding.status)

        finding.status = target_status
        if disposition == FindingDisposition.Disposition.DUPLICATE:
            finding.duplicate_of = canonical_duplicate
            update_fields = ['status', 'duplicate_of', 'updated_at']
        else:
            update_fields = ['status', 'updated_at']
        finding.save(update_fields=update_fields)

        VulnerabilityStatusHistory.objects.create(
            vulnerability=finding, old_status=previous_status, new_status=target_status,
            changed_by_id=actor_id,
            reason=f'Governed finding disposition {record.id}; policy={POLICY_VERSION}',
        )
        add_audit_entry(
            user=str(actor_id), action=AuditLog.Action.VULN_STATUS_CHANGE,
            target=str(finding.id), project=str(finding.project_id), resource_type='vulnerability',
            resource_repr=f'Governed finding disposition {record.id}',
            changes={'status': {'from': previous_status, 'to': target_status}},
            metadata={
                'operation': 'finding_disposition', 'disposition_id': str(record.id),
                'organization_id': str(organization.id), 'approving_role': membership.role,
                'risk_correlation_id': str(risk.id) if risk else None,
                'risk_correlation_sha256': risk_hash or None,
                'duplicate_of_id': str(canonical_duplicate.id) if canonical_duplicate else None,
                'review_at': normalized_review.isoformat() if normalized_review else None,
                'policy_version': POLICY_VERSION,
            },
        )
        return DispositionResult(record, False, True, previous_status)


def list_dispositions(*, finding_id: UUID | str) -> list[FindingDisposition]:
    return list(
        FindingDisposition.objects.filter(finding_id=finding_id)
        .select_related('organization', 'risk_correlation', 'duplicate_of', 'created_by')
        .order_by('-created_at')
    )
