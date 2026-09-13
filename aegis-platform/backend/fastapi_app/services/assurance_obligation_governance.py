from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.evidence.models import FindingDisposition
from enterprise.assurance_models import AssuranceObservation, AssuranceObligation, AssuranceObligationEvent
from enterprise.models import OrganizationMembership, TenantProject
from fastapi_app.services.policy_engine import evaluate_policy


_GOVERNANCE_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
}
_READ_ROLES = set(OrganizationMembership.Role.values)


class AssuranceObligationError(ValueError):
    pass


class StaleObligationVersion(AssuranceObligationError):
    pass


@dataclass(frozen=True)
class ObligationResult:
    obligation: AssuranceObligation
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _membership(project_id: str, user_id: str, roles: set[str]):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None or not link.organization.is_active:
        raise AssuranceObligationError('Project is not bound to an active enterprise tenant.')
    membership = OrganizationMembership.objects.filter(
        organization=link.organization,
        user_id=user_id,
        is_active=True,
        user__is_active=True,
        role__in=roles,
    ).first()
    if membership is None:
        raise PermissionError('Active tenant role does not permit this assurance obligation operation.')
    return link, membership


def _append_event_locked(obligation: AssuranceObligation, actor_id: str | None, event_type: str, payload: dict[str, Any]):
    previous = AssuranceObligationEvent.objects.filter(obligation=obligation).order_by('-id').first()
    previous_hash = previous.entry_hash if previous else ''
    envelope = {
        'obligation_id': str(obligation.id),
        'actor_id': str(actor_id or ''),
        'event_type': event_type,
        'payload': payload,
        'previous_hash': previous_hash,
    }
    return AssuranceObligationEvent.objects.create(
        obligation=obligation,
        actor_id=actor_id,
        event_type=event_type,
        payload=payload,
        previous_hash=previous_hash,
        entry_hash=_sha(envelope),
    )


def _policy_for_finding(finding) -> dict[str, Any]:
    return evaluate_policy({
        'riskBefore': int(round(float(finding.risk_score or 0))),
        'priority': int(round(float(finding.risk_score or 0))),
        'environment': str((finding.raw_data or {}).get('environment', '')).lower(),
    })


def _supersede_open_locked(*, finding_id, except_id=None, actor_id=None, reason: str):
    rows = AssuranceObligation.objects.select_for_update().filter(finding_id=finding_id, status=AssuranceObligation.Status.OPEN)
    if except_id:
        rows = rows.exclude(pk=except_id)
    for row in rows:
        row.status = AssuranceObligation.Status.SUPERSEDED
        row.version += 1
        row.save(update_fields=['status', 'version', 'updated_at'])
        _append_event_locked(row, actor_id, 'obligation.superseded', {'reason': reason, 'version': row.version})


def materialize_expired_risk_obligation(
    *, disposition_id: str, project_id: str, user_id: str, now: datetime | None = None,
) -> ObligationResult:
    now = now or timezone.now()
    if timezone.is_naive(now):
        raise AssuranceObligationError('now must be timezone-aware.')
    link, _ = _membership(project_id, user_id, _GOVERNANCE_ROLES)
    with transaction.atomic():
        TenantProject.objects.select_for_update().get(pk=link.pk)
        disposition = FindingDisposition.objects.select_for_update().select_related('finding', 'created_by').filter(
            pk=disposition_id,
            organization=link.organization,
            finding__project_id=project_id,
            disposition__in=[FindingDisposition.Disposition.ACCEPTED_RISK, FindingDisposition.Disposition.WONT_FIX],
        ).first()
        if disposition is None:
            raise AssuranceObligationError('Risk disposition not found in tenant/project scope.')
        latest = FindingDisposition.objects.filter(finding=disposition.finding).order_by('-created_at', '-id').first()
        if latest is None or latest.id != disposition.id:
            raise AssuranceObligationError('Only the latest immutable risk disposition can create a review obligation.')
        if disposition.review_at is None or disposition.review_at > now:
            raise AssuranceObligationError('Risk disposition review is not due yet.')

        source_sha = _sha({
            'disposition_id': str(disposition.id),
            'request_fingerprint': disposition.request_fingerprint,
            'policy_version': disposition.policy_version,
            'risk_correlation_sha256': disposition.risk_correlation_sha256,
            'review_at': disposition.review_at.isoformat(),
        })
        fingerprint = _sha({'source_type': 'risk_review', 'source_sha256': source_sha})
        existing = AssuranceObligation.objects.select_for_update().filter(source_fingerprint=fingerprint).first()
        if existing:
            return ObligationResult(existing, True)

        policy = _policy_for_finding(disposition.finding)
        generation = (AssuranceObligation.objects.filter(finding=disposition.finding).order_by('-generation').values_list('generation', flat=True).first() or 0) + 1
        _supersede_open_locked(
            finding_id=disposition.finding_id,
            actor_id=user_id,
            reason='A newer governed risk-review obligation became authoritative.',
        )
        obligation = AssuranceObligation.objects.create(
            organization=link.organization,
            project_id=project_id,
            finding=disposition.finding,
            source_type=AssuranceObligation.SourceType.RISK_REVIEW,
            source_disposition=disposition,
            source_sha256=source_sha,
            source_fingerprint=fingerprint,
            policy_id=policy['policyId'],
            policy_version=int(policy['policyVersion']),
            sla_hours=int(policy['slaHours']),
            due_at=disposition.review_at,
            owner=disposition.created_by,
            generation=generation,
        )
        _append_event_locked(obligation, user_id, 'obligation.created.risk_review', {
            'disposition_id': str(disposition.id),
            'review_at': disposition.review_at.isoformat(),
            'policy_id': obligation.policy_id,
            'policy_version': obligation.policy_version,
            'sla_hours': obligation.sla_hours,
            'source_sha256': source_sha,
            'generation': generation,
        })
        return ObligationResult(obligation, False)


def materialize_recurrence_obligation(
    *, observation_id: str, project_id: str, user_id: str,
) -> ObligationResult:
    link, _ = _membership(project_id, user_id, _GOVERNANCE_ROLES)
    with transaction.atomic():
        TenantProject.objects.select_for_update().get(pk=link.pk)
        observation = AssuranceObservation.objects.select_for_update(of=('self',)).select_related('finding', 'observed_by', 'prior_disposition').filter(
            pk=observation_id,
            project_id=project_id,
            organization=link.organization,
            classification=AssuranceObservation.Classification.RECURRENT,
            finding_present=True,
        ).first()
        if observation is None:
            raise AssuranceObligationError('Governed recurrent assurance observation not found in tenant/project.')
        source_sha = _sha({
            'observation_id': str(observation.id),
            'payload_sha256': observation.payload_sha256,
            'material_sha256': observation.material_sha256,
            'generation': observation.generation,
            'prior_disposition_id': str(observation.prior_disposition_id or ''),
            'prior_closure_id': str(observation.prior_closure_id or ''),
        })
        fingerprint = _sha({'source_type': 'recurrence', 'source_sha256': source_sha})
        existing = AssuranceObligation.objects.select_for_update().filter(source_fingerprint=fingerprint).first()
        if existing:
            return ObligationResult(existing, True)

        policy = _policy_for_finding(observation.finding)
        generation = (AssuranceObligation.objects.filter(finding=observation.finding).order_by('-generation').values_list('generation', flat=True).first() or 0) + 1
        _supersede_open_locked(
            finding_id=observation.finding_id,
            actor_id=user_id,
            reason='A recurrent assurance condition created a newer obligation generation.',
        )
        due_at = observation.observed_at + timedelta(hours=int(policy['slaHours']))
        obligation = AssuranceObligation.objects.create(
            organization=link.organization,
            project_id=project_id,
            finding=observation.finding,
            source_type=AssuranceObligation.SourceType.RECURRENCE,
            source_disposition=observation.prior_disposition,
            source_observation=observation,
            source_sha256=source_sha,
            source_fingerprint=fingerprint,
            policy_id=policy['policyId'],
            policy_version=int(policy['policyVersion']),
            sla_hours=int(policy['slaHours']),
            due_at=due_at,
            owner=observation.observed_by,
            generation=generation,
        )
        _append_event_locked(obligation, user_id, 'obligation.created.recurrence', {
            'observation_id': str(observation.id),
            'prior_disposition_id': str(observation.prior_disposition_id or ''),
            'prior_closure_id': str(observation.prior_closure_id or ''),
            'policy_id': obligation.policy_id,
            'policy_version': obligation.policy_version,
            'sla_hours': obligation.sla_hours,
            'due_at': due_at.isoformat(),
            'source_sha256': source_sha,
            'generation': generation,
        })
        return ObligationResult(obligation, False)


def evaluate_obligation_sla(*, project_id: str, user_id: str, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or timezone.now()
    if timezone.is_naive(now):
        raise AssuranceObligationError('now must be timezone-aware.')
    _membership(project_id, user_id, _GOVERNANCE_ROLES)
    changed: list[dict[str, Any]] = []
    ids = list(AssuranceObligation.objects.filter(project_id=project_id, status=AssuranceObligation.Status.OPEN).values_list('id', flat=True))
    for obligation_id in ids:
        with transaction.atomic():
            obligation = AssuranceObligation.objects.select_for_update().filter(pk=obligation_id, status=AssuranceObligation.Status.OPEN).first()
            if obligation is None:
                continue
            window_seconds = max(1, obligation.sla_hours * 3600)
            remaining = int((obligation.due_at - now).total_seconds())
            ratio = remaining / window_seconds
            desired = AssuranceObligation.SLAStatus.BREACHED if remaining <= 0 else AssuranceObligation.SLAStatus.AT_RISK if ratio <= 0.2 else AssuranceObligation.SLAStatus.ON_TRACK
            level = obligation.escalation_level
            if desired == AssuranceObligation.SLAStatus.AT_RISK and level < 1:
                level = 1
            if desired == AssuranceObligation.SLAStatus.BREACHED and level < 2:
                level = 2
            if desired == obligation.sla_status and level == obligation.escalation_level:
                continue
            old = obligation.sla_status
            obligation.sla_status = desired
            obligation.escalation_level = level
            obligation.version += 1
            obligation.save(update_fields=['sla_status', 'escalation_level', 'version', 'updated_at'])
            _append_event_locked(obligation, user_id, 'obligation.sla_changed', {
                'old': old,
                'new': desired,
                'escalation_level': level,
                'due_at': obligation.due_at.isoformat(),
                'remaining_seconds': remaining,
                'version': obligation.version,
            })
            changed.append({'obligation_id': str(obligation.id), 'sla_status': desired, 'escalation_level': level, 'version': obligation.version})
    return changed


def satisfy_obligation(
    *, obligation_id: str, project_id: str, user_id: str, expected_version: int, observation_id: str,
) -> ObligationResult:
    _membership(project_id, user_id, _GOVERNANCE_ROLES)
    with transaction.atomic():
        obligation = AssuranceObligation.objects.select_for_update().filter(pk=obligation_id, project_id=project_id).first()
        if obligation is None:
            raise AssuranceObligationError('Assurance obligation not found in project.')
        if obligation.status == AssuranceObligation.Status.SATISFIED and obligation.satisfied_observation_id == observation_id:
            return ObligationResult(obligation, True)
        if obligation.version != expected_version:
            raise StaleObligationVersion(f'Expected obligation version {expected_version}, current version is {obligation.version}.')
        if obligation.status != AssuranceObligation.Status.OPEN:
            raise AssuranceObligationError('Only open assurance obligations may be satisfied.')
        observation = AssuranceObservation.objects.filter(
            pk=observation_id,
            project_id=project_id,
            finding_id=obligation.finding_id,
            classification=AssuranceObservation.Classification.RESOLVED,
            finding_present=False,
        ).first()
        if observation is None:
            raise AssuranceObligationError('Satisfaction requires a resolved governed assurance observation for the same finding.')
        if observation.observed_at < obligation.created_at:
            raise AssuranceObligationError('Satisfaction observation predates the obligation.')
        obligation.status = AssuranceObligation.Status.SATISFIED
        obligation.satisfied_observation = observation
        obligation.satisfied_by_id = user_id
        obligation.satisfied_at = timezone.now()
        obligation.version += 1
        obligation.save(update_fields=['status', 'satisfied_observation', 'satisfied_by', 'satisfied_at', 'version', 'updated_at'])
        _append_event_locked(obligation, user_id, 'obligation.satisfied', {
            'observation_id': str(observation.id),
            'payload_sha256': observation.payload_sha256,
            'version': obligation.version,
        })
        return ObligationResult(obligation, False)


def verify_obligation_chain(*, obligation_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, _READ_ROLES)
    obligation = AssuranceObligation.objects.filter(pk=obligation_id, project_id=project_id).first()
    if obligation is None:
        raise AssuranceObligationError('Assurance obligation not found in project.')
    previous = ''
    rows = list(AssuranceObligationEvent.objects.filter(obligation=obligation).order_by('id'))
    for row in rows:
        if row.previous_hash != previous:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'previous_hash'}
        envelope = {
            'obligation_id': str(obligation.id),
            'actor_id': str(row.actor_id or ''),
            'event_type': row.event_type,
            'payload': row.payload,
            'previous_hash': row.previous_hash,
        }
        expected = _sha(envelope)
        if row.entry_hash != expected:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'entry_hash'}
        previous = row.entry_hash
    return {'valid': True, 'entries': len(rows), 'head': previous}


def get_obligation(*, obligation_id: str, project_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id, _READ_ROLES)
    obligation = AssuranceObligation.objects.filter(pk=obligation_id, project_id=project_id).first()
    if obligation is None:
        raise AssuranceObligationError('Assurance obligation not found in project.')
    return {
        'id': str(obligation.id),
        'finding_id': str(obligation.finding_id),
        'source_type': obligation.source_type,
        'source_disposition_id': str(obligation.source_disposition_id) if obligation.source_disposition_id else None,
        'source_observation_id': str(obligation.source_observation_id) if obligation.source_observation_id else None,
        'source_sha256': obligation.source_sha256,
        'policy_id': obligation.policy_id,
        'policy_version': obligation.policy_version,
        'sla_hours': obligation.sla_hours,
        'due_at': obligation.due_at.isoformat(),
        'status': obligation.status,
        'sla_status': obligation.sla_status,
        'escalation_level': obligation.escalation_level,
        'generation': obligation.generation,
        'version': obligation.version,
        'owner_id': str(obligation.owner_id),
        'satisfied_observation_id': str(obligation.satisfied_observation_id) if obligation.satisfied_observation_id else None,
    }
