from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.evidence.models import FindingDisposition
from django_project.vulnerabilities.models import Vulnerability
from enterprise.assurance_models import AssuranceObservation
from enterprise.assurance_obligation_models import AssuranceObligation, AssuranceObligationEvent
from enterprise.models import ContinuousAssuranceSchedule, Organization, OrganizationMembership, TenantProject
from fastapi_app.services.policy_engine import evaluate_policy

POLICY_VERSION = 'assurance-obligation.v3'
DUE_WINDOW = timedelta(hours=24)
RISK_DISPOSITIONS = {FindingDisposition.Disposition.ACCEPTED_RISK, FindingDisposition.Disposition.WONT_FIX}
GOVERNANCE_ROLES = {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN, OrganizationMembership.Role.MANAGER}
REVIEWER_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
    OrganizationMembership.Role.ANALYST,
}


class AssuranceObligationError(ValueError):
    pass


@dataclass(frozen=True)
class AssuranceObligationResult:
    obligation: AssuranceObligation
    replayed: bool


@dataclass(frozen=True)
class AssuranceReconcileResult:
    materialized: int
    refreshed: int
    satisfied: int
    overdue: int
    superseded: int


def _sha(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _tenant_membership(*, project_id: str, user_id: str, mutation: bool = True):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None or not link.organization.is_active:
        raise AssuranceObligationError('Project is not bound to an active enterprise tenant.')
    membership = OrganizationMembership.objects.filter(organization=link.organization, user_id=user_id, is_active=True, user__is_active=True).first()
    if membership is None:
        raise PermissionError('Active tenant membership is required for assurance obligation access.')
    if mutation and membership.role not in GOVERNANCE_ROLES:
        raise PermissionError('Tenant role does not permit assurance obligation governance mutation.')
    return link, membership


def _lock_scope(link: TenantProject) -> TenantProject:
    organization = (
        Organization.objects.select_for_update(of=('self',))
        .filter(pk=link.organization_id, is_active=True)
        .first()
    )
    if organization is None:
        raise AssuranceObligationError('Project tenant is no longer active.')
    locked = (
        TenantProject.objects.select_for_update(of=('self',))
        .select_related('organization', 'project')
        .filter(pk=link.pk, project_id=link.project_id, organization=organization)
        .first()
    )
    if locked is None:
        raise AssuranceObligationError('Project tenant binding changed during obligation governance.')
    return locked


def _select_schedule(*, organization_id, project_id, asset_id, schedule_id: str | None):
    schedules = ContinuousAssuranceSchedule.objects.select_for_update().filter(organization_id=organization_id, project_id=project_id, asset_id=asset_id, enabled=True, authorization_decision__isnull=False)
    schedule = schedules.filter(pk=schedule_id).first() if schedule_id else schedules.order_by('next_run', 'created_at', 'id').first()
    if schedule is None:
        raise AssuranceObligationError('Governed risk disposition requires an enabled continuous assurance schedule for revalidation.')
    return schedule


def _source_disposition(obligation: AssuranceObligation):
    return obligation.disposition or obligation.source_disposition


def _append_event(*, obligation: AssuranceObligation, event_type: str, actor_id: str, payload: dict[str, Any], execution_id=None, observation_id=None):
    sequence = (AssuranceObligationEvent.objects.filter(obligation=obligation).order_by('-sequence').values_list('sequence', flat=True).first() or 0) + 1
    source_disposition = _source_disposition(obligation)
    canonical_payload = {
        **payload,
        'policy_version': POLICY_VERSION,
        'obligation_id': str(obligation.id),
        'kind': obligation.kind,
        'disposition_id': str(obligation.disposition_id) if obligation.disposition_id else None,
        'source_disposition_id': str(obligation.source_disposition_id) if obligation.source_disposition_id else None,
        'source_observation_id': str(obligation.source_observation_id) if obligation.source_observation_id else None,
        'schedule_id': str(obligation.schedule_id),
        'sequence': sequence,
        'event_type': event_type,
    }
    payload_sha = _sha(canonical_payload)
    return AssuranceObligationEvent.objects.create(
        obligation=obligation,
        sequence=sequence,
        event_type=event_type,
        disposition_id=obligation.disposition_id,
        schedule_id=obligation.schedule_id,
        execution_id=execution_id,
        observation_id=observation_id,
        risk_correlation_id=source_disposition.risk_correlation_id if source_disposition else None,
        payload=canonical_payload,
        payload_sha256=payload_sha,
        replay_fingerprint=_sha({'obligation_id': str(obligation.id), 'sequence': sequence, 'event_type': event_type, 'payload_sha256': payload_sha}),
        actor_id=actor_id,
    )


def _latest_disposition_locked(finding: Vulnerability):
    latest = FindingDisposition.objects.select_for_update().filter(finding=finding).order_by('-created_at', '-id').first()
    if latest is None:
        raise AssuranceObligationError('Finding has no governed disposition.')
    if latest.disposition not in RISK_DISPOSITIONS or latest.review_at is None:
        raise AssuranceObligationError('Latest finding disposition does not create a review obligation.')
    return latest


def _target_status(*, due_at, now):
    if now >= due_at:
        return AssuranceObligation.Status.OVERDUE
    if due_at <= now + DUE_WINDOW:
        return AssuranceObligation.Status.DUE
    return AssuranceObligation.Status.OPEN


def _policy_for_finding(finding: Vulnerability) -> dict[str, Any]:
    return evaluate_policy({
        'riskBefore': int(round(float(finding.risk_score or 0))),
        'priority': int(round(float(finding.risk_score or 0))),
        'environment': str((finding.raw_data or {}).get('environment', '')).lower(),
    })


def _priority_for_policy(policy: dict[str, Any]) -> str:
    policy_id = str(policy.get('policyId') or '').strip().lower()
    if policy_id in {'critical-production', 'critical'}:
        return AssuranceObligation.Priority.P0_CRITICAL
    if policy_id == 'high':
        return AssuranceObligation.Priority.P1_HIGH
    if policy_id == 'medium':
        return AssuranceObligation.Priority.P2_MEDIUM
    return AssuranceObligation.Priority.P3_LOW


def _sla_target(obligation: AssuranceObligation, now) -> str:
    if obligation.status in {AssuranceObligation.Status.SATISFIED, AssuranceObligation.Status.SUPERSEDED}:
        return AssuranceObligation.SLAStatus.CLOSED
    if now >= obligation.due_at or obligation.status == AssuranceObligation.Status.OVERDUE:
        return AssuranceObligation.SLAStatus.BREACHED
    if obligation.due_at <= now + DUE_WINDOW or obligation.status == AssuranceObligation.Status.DUE:
        return AssuranceObligation.SLAStatus.AT_RISK
    return AssuranceObligation.SLAStatus.ON_TRACK


def _sync_sla_locked(*, obligation: AssuranceObligation, actor_id: str, now) -> AssuranceObligation:
    desired = _sla_target(obligation, now)
    current = obligation.sla_status
    level = int(obligation.escalation_level or 0)
    desired_level = level
    if desired == AssuranceObligation.SLAStatus.AT_RISK:
        desired_level = max(level, 1)
    elif desired == AssuranceObligation.SLAStatus.BREACHED:
        desired_level = max(level, 2)

    if current == desired and desired_level == level:
        return obligation

    level_increased = desired_level > level
    obligation.sla_status = desired
    obligation.escalation_level = desired_level
    if level_increased:
        obligation.last_escalated_at = now
    obligation.version += 1
    update_fields = ['sla_status', 'escalation_level', 'version', 'updated_at']
    if level_increased:
        update_fields.append('last_escalated_at')
    obligation.save(update_fields=update_fields)

    event_type = None
    if current != desired:
        event_type = {
            AssuranceObligation.SLAStatus.AT_RISK: AssuranceObligationEvent.EventType.SLA_AT_RISK,
            AssuranceObligation.SLAStatus.BREACHED: AssuranceObligationEvent.EventType.SLA_BREACHED,
            AssuranceObligation.SLAStatus.CLOSED: AssuranceObligationEvent.EventType.SLA_CLOSED,
        }.get(desired)
    if event_type is not None:
        _append_event(
            obligation=obligation,
            event_type=event_type,
            actor_id=actor_id,
            payload={
                'previous_sla_status': current,
                'sla_status': desired,
                'escalation_level': desired_level,
                'escalation_targets': list(obligation.escalation_targets or []),
                'due_at': obligation.due_at.isoformat(),
                'evaluated_at': now.isoformat(),
            },
        )
    return obligation


def _default_assignment(membership: OrganizationMembership | None):
    if membership is None or membership.role not in REVIEWER_ROLES:
        return None
    return membership


def _configure_existing_work_queue_locked(
    *,
    obligation: AssuranceObligation,
    finding: Vulnerability,
    membership: OrganizationMembership | None,
    actor_id: str,
    now,
) -> None:
    policy = _policy_for_finding(finding)
    updates: list[str] = []
    assigned_now = False
    if not obligation.policy_id:
        obligation.policy_id = str(policy['policyId'])
        obligation.policy_version = int(policy['policyVersion'])
        obligation.priority = _priority_for_policy(policy)
        obligation.escalation_targets = list(policy.get('escalationTargets') or [])
        updates.extend(['policy_id', 'policy_version', 'priority', 'escalation_targets'])
    assignee = _default_assignment(membership)
    if obligation.assigned_to_id is None and assignee is not None:
        obligation.assigned_to = assignee
        obligation.assigned_by_id = actor_id
        obligation.assigned_at = now
        updates.extend(['assigned_to', 'assigned_by', 'assigned_at'])
        assigned_now = True
    if updates:
        obligation.version += 1
        updates.extend(['version', 'updated_at'])
        obligation.save(update_fields=list(dict.fromkeys(updates)))
    if assigned_now:
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.ASSIGNED,
            actor_id=actor_id,
            payload={
                'assignee_membership_id': str(obligation.assigned_to_id),
                'assignee_user_id': str(obligation.assigned_to.user_id),
                'assignment_reason': 'materialization_default_reviewer',
            },
        )


def _supersede_active_locked(*, finding_id, actor_id: str, now, reason: str, except_id=None):
    rows = AssuranceObligation.objects.select_for_update().filter(
        finding_id=finding_id,
        status__in=[AssuranceObligation.Status.OPEN, AssuranceObligation.Status.DUE, AssuranceObligation.Status.OVERDUE],
    )
    if except_id:
        rows = rows.exclude(pk=except_id)
    for item in rows:
        item.status = AssuranceObligation.Status.SUPERSEDED
        item.version += 1
        item.superseded_at = now
        item.save(update_fields=['status', 'version', 'superseded_at', 'updated_at'])
        _append_event(obligation=item, event_type=AssuranceObligationEvent.EventType.SUPERSEDED, actor_id=actor_id, payload={'reason': reason})
        _sync_sla_locked(obligation=item, actor_id=actor_id, now=now)


def _record_observation_locked(*, obligation: AssuranceObligation, observation: AssuranceObservation, actor_id: str):
    if observation.id == obligation.last_observation_id:
        return obligation
    obligation.last_observation = observation
    obligation.last_execution_id = observation.execution_id
    obligation.version += 1
    if observation.classification == AssuranceObservation.Classification.RESOLVED and not observation.finding_present:
        obligation.status = AssuranceObligation.Status.SATISFIED
        obligation.satisfied_at = observation.observed_at
        obligation.save(update_fields=['last_observation', 'last_execution', 'version', 'status', 'satisfied_at', 'updated_at'])
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.SATISFIED,
            actor_id=actor_id,
            execution_id=observation.execution_id,
            observation_id=observation.id,
            payload={'classification': observation.classification, 'finding_present': observation.finding_present},
        )
        _sync_sla_locked(obligation=obligation, actor_id=actor_id, now=observation.observed_at)
        return obligation
    obligation.save(update_fields=['last_observation', 'last_execution', 'version', 'updated_at'])
    _append_event(
        obligation=obligation,
        event_type=AssuranceObligationEvent.EventType.REVALIDATED_PRESENT,
        actor_id=actor_id,
        execution_id=observation.execution_id,
        observation_id=observation.id,
        payload={'classification': observation.classification, 'finding_present': observation.finding_present},
    )
    _sync_sla_locked(obligation=obligation, actor_id=actor_id, now=observation.observed_at)
    return obligation


def _refresh_locked(*, obligation: AssuranceObligation, actor_id: str, now):
    if obligation.status in {AssuranceObligation.Status.SATISFIED, AssuranceObligation.Status.SUPERSEDED}:
        return _sync_sla_locked(obligation=obligation, actor_id=actor_id, now=now)

    if obligation.kind == AssuranceObligation.Kind.DISPOSITION_REVIEW:
        latest = FindingDisposition.objects.select_for_update().filter(finding_id=obligation.finding_id).order_by('-created_at', '-id').first()
        if latest is None or latest.id != obligation.disposition_id:
            obligation.status = AssuranceObligation.Status.SUPERSEDED
            obligation.version += 1
            obligation.superseded_at = now
            obligation.save(update_fields=['status', 'version', 'superseded_at', 'updated_at'])
            _append_event(obligation=obligation, event_type=AssuranceObligationEvent.EventType.SUPERSEDED, actor_id=actor_id, payload={'superseded_by_disposition_id': str(latest.id) if latest else None})
            _sync_sla_locked(obligation=obligation, actor_id=actor_id, now=now)
            return obligation
        observed_after = obligation.disposition.created_at
    elif obligation.kind == AssuranceObligation.Kind.RECURRENCE_REVIEW:
        if obligation.source_observation_id is None:
            raise AssuranceObligationError('Recurrence obligation is missing immutable source observation lineage.')
        observed_after = obligation.source_observation.observed_at
    else:
        raise AssuranceObligationError('Unsupported assurance obligation kind.')

    observation = AssuranceObservation.objects.filter(
        project_id=obligation.project_id,
        finding_id=obligation.finding_id,
        execution__schedule_id=obligation.schedule_id,
        observed_at__gt=observed_after,
    ).order_by('-observed_at', '-id').first()
    if observation is not None:
        _record_observation_locked(obligation=obligation, observation=observation, actor_id=actor_id)
        if obligation.status == AssuranceObligation.Status.SATISFIED:
            return obligation

    target = _target_status(due_at=obligation.due_at, now=now)
    if target != obligation.status:
        obligation.status = target
        obligation.version += 1
        obligation.save(update_fields=['status', 'version', 'updated_at'])
        event_type = AssuranceObligationEvent.EventType.OVERDUE if target == AssuranceObligation.Status.OVERDUE else AssuranceObligationEvent.EventType.DUE
        _append_event(obligation=obligation, event_type=event_type, actor_id=actor_id, payload={'due_at': obligation.due_at.isoformat(), 'evaluated_at': now.isoformat()})
    return _sync_sla_locked(obligation=obligation, actor_id=actor_id, now=now)


def materialize_assurance_obligation(*, project_id: str, finding_id: str, user_id: str, schedule_id: str | None = None, now=None) -> AssuranceObligationResult:
    now = now or timezone.now()
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=True)
    with transaction.atomic():
        link = _lock_scope(link)
        finding = Vulnerability.objects.select_for_update().filter(pk=finding_id, project_id=project_id).first()
        if finding is None:
            raise AssuranceObligationError('Finding was not found in project scope.')
        disposition = _latest_disposition_locked(finding)
        schedule = _select_schedule(organization_id=link.organization_id, project_id=project_id, asset_id=finding.asset_id, schedule_id=schedule_id)
        existing = AssuranceObligation.objects.select_related('disposition', 'source_disposition', 'source_observation').select_for_update(of=('self',)).filter(disposition=disposition).first()
        if existing is not None:
            if existing.schedule_id != schedule.id:
                raise AssuranceObligationError('Existing immutable disposition obligation is bound to a different assurance schedule.')
            _configure_existing_work_queue_locked(
                obligation=existing,
                finding=finding,
                membership=membership,
                actor_id=user_id,
                now=now,
            )
            _refresh_locked(obligation=existing, actor_id=user_id, now=now)
            return AssuranceObligationResult(existing, True)
        policy = _policy_for_finding(finding)
        assignee = _default_assignment(membership)
        generation = (AssuranceObligation.objects.filter(finding=finding).order_by('-generation').values_list('generation', flat=True).first() or 0) + 1
        _supersede_active_locked(finding_id=finding.id, actor_id=user_id, now=now, reason='A newer governed risk disposition became authoritative.')
        obligation = AssuranceObligation.objects.create(
            organization=link.organization,
            project_id=project_id,
            asset_id=finding.asset_id,
            finding=finding,
            disposition=disposition,
            schedule=schedule,
            kind=AssuranceObligation.Kind.DISPOSITION_REVIEW,
            due_at=disposition.review_at,
            generation=generation,
            created_by_id=user_id,
            assigned_to=assignee,
            assigned_by_id=user_id if assignee is not None else None,
            assigned_at=now if assignee is not None else None,
            priority=_priority_for_policy(policy),
            policy_id=str(policy['policyId']),
            policy_version=int(policy['policyVersion']),
            escalation_targets=list(policy.get('escalationTargets') or []),
        )
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.CREATED,
            actor_id=user_id,
            payload={
                'disposition': disposition.disposition,
                'due_at': disposition.review_at.isoformat(),
                'risk_correlation_id': str(disposition.risk_correlation_id),
                'policy_id': policy['policyId'],
                'policy_version_selected': policy['policyVersion'],
                'priority': obligation.priority,
                'escalation_targets': list(obligation.escalation_targets or []),
            },
        )
        if assignee is not None:
            _append_event(
                obligation=obligation,
                event_type=AssuranceObligationEvent.EventType.ASSIGNED,
                actor_id=user_id,
                payload={
                    'assignee_membership_id': str(assignee.id),
                    'assignee_user_id': str(assignee.user_id),
                    'assignment_reason': 'materialization_default_reviewer',
                },
            )
        _refresh_locked(obligation=obligation, actor_id=user_id, now=now)
        return AssuranceObligationResult(obligation, False)


def materialize_recurrence_obligation(*, project_id: str, observation_id: str, user_id: str, now=None) -> AssuranceObligationResult:
    now = now or timezone.now()
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=False)
    with transaction.atomic():
        link = _lock_scope(link)
        observation = AssuranceObservation.objects.select_related('finding', 'execution__schedule', 'prior_disposition').select_for_update(of=('self',)).filter(
            pk=observation_id,
            project_id=project_id,
            organization=link.organization,
            classification=AssuranceObservation.Classification.RECURRENT,
            finding_present=True,
        ).first()
        if observation is None:
            raise AssuranceObligationError('Governed recurrent assurance observation not found in tenant/project.')
        schedule = observation.execution.schedule
        if schedule.organization_id != link.organization_id or str(schedule.project_id) != str(project_id) or schedule.asset_id != observation.asset_id:
            raise AssuranceObligationError('Recurrence observation schedule lineage is outside tenant/project/asset scope.')
        existing = AssuranceObligation.objects.select_related('source_observation').select_for_update(of=('self',)).filter(source_observation=observation).first()
        if existing is not None:
            _configure_existing_work_queue_locked(
                obligation=existing,
                finding=observation.finding,
                membership=membership,
                actor_id=user_id,
                now=now,
            )
            _refresh_locked(obligation=existing, actor_id=user_id, now=now)
            return AssuranceObligationResult(existing, True)
        policy = _policy_for_finding(observation.finding)
        assignee = _default_assignment(membership)
        generation = (AssuranceObligation.objects.filter(finding=observation.finding).order_by('-generation').values_list('generation', flat=True).first() or 0) + 1
        _supersede_active_locked(
            finding_id=observation.finding_id,
            actor_id=user_id,
            now=now,
            reason='A recurrent assurance condition created a newer obligation generation.',
        )
        due_at = observation.observed_at + timedelta(hours=int(policy['slaHours']))
        obligation = AssuranceObligation.objects.create(
            organization=link.organization,
            project_id=project_id,
            asset_id=observation.asset_id,
            finding=observation.finding,
            disposition=None,
            source_disposition=observation.prior_disposition,
            source_observation=observation,
            schedule=schedule,
            kind=AssuranceObligation.Kind.RECURRENCE_REVIEW,
            due_at=due_at,
            generation=generation,
            created_by_id=user_id,
            assigned_to=assignee,
            assigned_by_id=user_id if assignee is not None else None,
            assigned_at=now if assignee is not None else None,
            priority=_priority_for_policy(policy),
            policy_id=str(policy['policyId']),
            policy_version=int(policy['policyVersion']),
            escalation_targets=list(policy.get('escalationTargets') or []),
        )
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.CREATED,
            actor_id=user_id,
            execution_id=observation.execution_id,
            observation_id=observation.id,
            payload={
                'classification': observation.classification,
                'generation': observation.generation,
                'policy_id': policy['policyId'],
                'policy_version_selected': policy['policyVersion'],
                'sla_hours': int(policy['slaHours']),
                'due_at': due_at.isoformat(),
                'prior_disposition_id': str(observation.prior_disposition_id) if observation.prior_disposition_id else None,
                'prior_closure_id': str(observation.prior_closure_id) if observation.prior_closure_id else None,
            },
        )
        if assignee is not None:
            _append_event(
                obligation=obligation,
                event_type=AssuranceObligationEvent.EventType.ASSIGNED,
                actor_id=user_id,
                execution_id=observation.execution_id,
                observation_id=observation.id,
                payload={
                    'assignee_membership_id': str(assignee.id),
                    'assignee_user_id': str(assignee.user_id),
                    'assignment_reason': 'recurrence_default_reviewer',
                },
            )
        _refresh_locked(obligation=obligation, actor_id=user_id, now=now)
        return AssuranceObligationResult(obligation, False)


def refresh_assurance_obligation(*, project_id: str, obligation_id: str, user_id: str, now=None):
    now = now or timezone.now()
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=True)
    with transaction.atomic():
        link = _lock_scope(link)
        obligation = AssuranceObligation.objects.select_related('disposition', 'source_disposition', 'source_observation', 'finding').select_for_update(of=('self',)).filter(pk=obligation_id, project_id=project_id, organization=link.organization).first()
        if obligation is None:
            raise AssuranceObligationError('Assurance obligation not found in tenant/project.')
        _configure_existing_work_queue_locked(
            obligation=obligation,
            finding=obligation.finding,
            membership=membership,
            actor_id=user_id,
            now=now,
        )
        return _refresh_locked(obligation=obligation, actor_id=user_id, now=now)


def reconcile_project_assurance_obligations(*, project_id: str, user_id: str, now=None) -> AssuranceReconcileResult:
    now = now or timezone.now()
    _tenant_membership(project_id=project_id, user_id=user_id, mutation=True)
    latest_by_finding = {}
    for disposition in FindingDisposition.objects.filter(finding__project_id=project_id).order_by('finding_id', '-created_at', '-id'):
        latest_by_finding.setdefault(str(disposition.finding_id), disposition)
    materialized = 0
    for disposition in latest_by_finding.values():
        if disposition.disposition not in RISK_DISPOSITIONS or disposition.review_at is None:
            continue
        result = materialize_assurance_obligation(project_id=project_id, finding_id=str(disposition.finding_id), user_id=user_id, now=now)
        materialized += int(not result.replayed)
    refreshed = 0
    ids = list(AssuranceObligation.objects.filter(project_id=project_id, status__in=[AssuranceObligation.Status.OPEN, AssuranceObligation.Status.DUE, AssuranceObligation.Status.OVERDUE]).values_list('id', flat=True))
    for obligation_id in ids:
        refresh_assurance_obligation(project_id=project_id, obligation_id=str(obligation_id), user_id=user_id, now=now)
        refreshed += 1
    current = AssuranceObligation.objects.filter(project_id=project_id)
    return AssuranceReconcileResult(materialized=materialized, refreshed=refreshed, satisfied=current.filter(status=AssuranceObligation.Status.SATISFIED).count(), overdue=current.filter(status=AssuranceObligation.Status.OVERDUE).count(), superseded=current.filter(status=AssuranceObligation.Status.SUPERSEDED).count())


def _require_obligation_version(obligation: AssuranceObligation, expected_version: int) -> None:
    if int(expected_version) < 1:
        raise AssuranceObligationError('expected_version must be at least one.')
    if int(obligation.version) != int(expected_version):
        raise AssuranceObligationError(
            f'Expected obligation version {expected_version}, current version is {obligation.version}.'
        )


def _locked_obligation(*, link: TenantProject, project_id: str, obligation_id: str):
    return (
        AssuranceObligation.objects
        .select_related(
            'finding',
            'disposition',
            'source_disposition',
            'source_observation',
            'schedule',
            'assigned_to',
            'assigned_to__user',
            'assigned_by',
            'acknowledged_by',
        )
        .select_for_update(of=('self',))
        .filter(pk=obligation_id, project_id=project_id, organization=link.organization)
        .first()
    )


def assign_assurance_obligation(
    *,
    project_id: str,
    obligation_id: str,
    user_id: str,
    assignee_membership_id: str,
    expected_version: int,
    now=None,
):
    now = now or timezone.now()
    link, _actor_membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=True)
    with transaction.atomic():
        link = _lock_scope(link)
        obligation = _locked_obligation(link=link, project_id=project_id, obligation_id=obligation_id)
        if obligation is None:
            raise AssuranceObligationError('Assurance obligation not found in tenant/project.')
        assignee = (
            OrganizationMembership.objects.select_for_update(of=('self',))
            .select_related('user')
            .filter(
                pk=assignee_membership_id,
                organization=link.organization,
                is_active=True,
                user__is_active=True,
                role__in=REVIEWER_ROLES,
            )
            .first()
        )
        if assignee is None:
            raise AssuranceObligationError('Assignee is not an active reviewer in this tenant.')
        is_project_member = (
            str(link.project.owner_id) == str(assignee.user_id)
            or link.project.members.filter(pk=assignee.user_id).exists()
        )
        if not is_project_member:
            raise AssuranceObligationError('Assignee is not a member of the governed project.')
        if obligation.assigned_to_id == assignee.id:
            return obligation
        if obligation.status in {AssuranceObligation.Status.SATISFIED, AssuranceObligation.Status.SUPERSEDED}:
            raise AssuranceObligationError('Terminal assurance obligations cannot be reassigned.')
        _require_obligation_version(obligation, expected_version)

        previous_membership_id = obligation.assigned_to_id
        previous_user_id = obligation.assigned_to.user_id if obligation.assigned_to_id else None
        obligation.assigned_to = assignee
        obligation.assigned_by_id = user_id
        obligation.assigned_at = now
        obligation.acknowledged_by = None
        obligation.acknowledged_at = None
        obligation.version += 1
        obligation.save(update_fields=[
            'assigned_to', 'assigned_by', 'assigned_at',
            'acknowledged_by', 'acknowledged_at', 'version', 'updated_at',
        ])
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.ASSIGNED,
            actor_id=user_id,
            payload={
                'previous_assignee_membership_id': str(previous_membership_id) if previous_membership_id else None,
                'previous_assignee_user_id': str(previous_user_id) if previous_user_id else None,
                'assignee_membership_id': str(assignee.id),
                'assignee_user_id': str(assignee.user_id),
                'expected_version': int(expected_version),
            },
        )
        return _sync_sla_locked(obligation=obligation, actor_id=user_id, now=now)


def acknowledge_assurance_obligation(
    *,
    project_id: str,
    obligation_id: str,
    user_id: str,
    expected_version: int,
    now=None,
):
    now = now or timezone.now()
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=False)
    with transaction.atomic():
        link = _lock_scope(link)
        obligation = _locked_obligation(link=link, project_id=project_id, obligation_id=obligation_id)
        if obligation is None:
            raise AssuranceObligationError('Assurance obligation not found in tenant/project.')
        if obligation.acknowledged_by_id == membership.user_id and obligation.acknowledged_at is not None:
            return obligation
        if obligation.status in {AssuranceObligation.Status.SATISFIED, AssuranceObligation.Status.SUPERSEDED}:
            raise AssuranceObligationError('Terminal assurance obligations cannot be acknowledged.')
        if obligation.assigned_to_id is None or obligation.assigned_to.user_id != membership.user_id:
            raise PermissionError('Only the currently assigned reviewer may acknowledge this obligation.')
        _require_obligation_version(obligation, expected_version)

        obligation.acknowledged_by_id = membership.user_id
        obligation.acknowledged_at = now
        obligation.version += 1
        obligation.save(update_fields=['acknowledged_by', 'acknowledged_at', 'version', 'updated_at'])
        _append_event(
            obligation=obligation,
            event_type=AssuranceObligationEvent.EventType.ACKNOWLEDGED,
            actor_id=user_id,
            payload={
                'assignee_membership_id': str(obligation.assigned_to_id),
                'acknowledged_by_user_id': str(membership.user_id),
                'expected_version': int(expected_version),
                'acknowledged_at': now.isoformat(),
            },
        )
        return _sync_sla_locked(obligation=obligation, actor_id=user_id, now=now)


def _obligation_view(row: AssuranceObligation, *, viewer_user_id: str | None = None) -> dict[str, Any]:
    assigned = None
    if row.assigned_to_id:
        assigned = {
            'membership_id': str(row.assigned_to_id),
            'user_id': str(row.assigned_to.user_id),
            'role': row.assigned_to.role,
            'email': str(row.assigned_to.user.email),
        }
    return {
        'id': str(row.id),
        'queue_item_id': f'assurance-obligation:{row.id}',
        'finding_id': str(row.finding_id),
        'kind': row.kind,
        'disposition_id': str(row.disposition_id) if row.disposition_id else None,
        'source_disposition_id': str(row.source_disposition_id) if row.source_disposition_id else None,
        'source_observation_id': str(row.source_observation_id) if row.source_observation_id else None,
        'disposition': row.disposition.disposition if row.disposition_id else None,
        'schedule_id': str(row.schedule_id),
        'status': row.status,
        'priority': row.priority,
        'sla_status': row.sla_status,
        'escalation_level': row.escalation_level,
        'escalation_targets': list(row.escalation_targets or []),
        'last_escalated_at': row.last_escalated_at.isoformat() if row.last_escalated_at else None,
        'policy_id': row.policy_id,
        'policy_version': row.policy_version,
        'due_at': row.due_at.isoformat(),
        'assigned_to': assigned,
        'assigned_at': row.assigned_at.isoformat() if row.assigned_at else None,
        'assigned_by_user_id': str(row.assigned_by_id) if row.assigned_by_id else None,
        'acknowledged_at': row.acknowledged_at.isoformat() if row.acknowledged_at else None,
        'acknowledged_by_user_id': str(row.acknowledged_by_id) if row.acknowledged_by_id else None,
        'acknowledged': row.acknowledged_at is not None,
        'assigned_to_me': bool(viewer_user_id and row.assigned_to_id and str(row.assigned_to.user_id) == str(viewer_user_id)),
        'generation': row.generation,
        'version': row.version,
        'last_execution_id': str(row.last_execution_id) if row.last_execution_id else None,
        'last_observation_id': str(row.last_observation_id) if row.last_observation_id else None,
        'satisfied_at': row.satisfied_at.isoformat() if row.satisfied_at else None,
        'superseded_at': row.superseded_at.isoformat() if row.superseded_at else None,
    }


def _obligation_rows(*, project_id: str, organization, include_terminal: bool = True):
    rows = (
        AssuranceObligation.objects
        .filter(project_id=project_id, organization=organization)
        .select_related(
            'disposition',
            'source_disposition',
            'source_observation',
            'schedule',
            'assigned_to',
            'assigned_to__user',
            'assigned_by',
            'acknowledged_by',
        )
    )
    if not include_terminal:
        rows = rows.exclude(status__in=[
            AssuranceObligation.Status.SATISFIED,
            AssuranceObligation.Status.SUPERSEDED,
        ])
    return rows


def list_review_work_queue(
    *,
    project_id: str,
    user_id: str,
    mine: bool = False,
    include_terminal: bool = False,
):
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=False)
    rows = _obligation_rows(
        project_id=project_id,
        organization=link.organization,
        include_terminal=include_terminal,
    )
    if mine:
        rows = rows.filter(assigned_to=membership)
    items = list(rows)
    priority_rank = {
        AssuranceObligation.Priority.P0_CRITICAL: 0,
        AssuranceObligation.Priority.P1_HIGH: 1,
        AssuranceObligation.Priority.P2_MEDIUM: 2,
        AssuranceObligation.Priority.P3_LOW: 3,
    }
    status_rank = {
        AssuranceObligation.Status.OVERDUE: 0,
        AssuranceObligation.Status.DUE: 1,
        AssuranceObligation.Status.OPEN: 2,
        AssuranceObligation.Status.SATISFIED: 3,
        AssuranceObligation.Status.SUPERSEDED: 4,
    }
    items.sort(key=lambda row: (
        status_rank.get(row.status, 9),
        priority_rank.get(row.priority, 9),
        row.due_at,
        row.created_at,
        str(row.id),
    ))
    return [_obligation_view(row, viewer_user_id=str(membership.user_id)) for row in items]


def list_assurance_obligations(*, project_id: str, user_id: str):
    link, membership = _tenant_membership(project_id=project_id, user_id=user_id, mutation=False)
    rows = _obligation_rows(
        project_id=project_id,
        organization=link.organization,
        include_terminal=True,
    ).order_by('due_at', 'created_at')
    return [_obligation_view(row, viewer_user_id=str(membership.user_id)) for row in rows]
