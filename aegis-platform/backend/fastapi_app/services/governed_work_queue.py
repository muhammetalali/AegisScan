from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from django_project.projects.models import Project
from enterprise.assurance_obligation_models import AssuranceObligation
from enterprise.detection_models import DetectionPublicationDelivery
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.models import DecisionAction, InvestigationCase, Organization, OrganizationMembership, TenantProject
from enterprise.soc_models import InvestigationCaseState
from enterprise.work_queue_models import GovernedWorkClaim, GovernedWorkClaimEvent


WORK_QUEUE_POLICY_VERSION = 'agom.work-queue.v1'
MUTATION_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
    OrganizationMembership.Role.ANALYST,
}
_IDEMPOTENCY_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$')
_SOURCE_TYPES = {choice.value for choice in GovernedWorkClaim.SourceType}


class GovernedWorkQueueError(ValueError):
    pass


class GovernedWorkQueueConflict(GovernedWorkQueueError):
    pass


class StaleGovernedWorkClaimVersion(GovernedWorkQueueConflict):
    pass


@dataclass(frozen=True)
class WorkMutationResult:
    snapshot: dict[str, Any]
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _normalize_key(value: str) -> str:
    key = str(value or '').strip()
    if not _IDEMPOTENCY_RE.fullmatch(key):
        raise GovernedWorkQueueError('Idempotency key must be 8-128 safe ASCII characters.')
    return key


def _normalize_source_type(value: str) -> str:
    normalized = str(value or '').strip().lower()
    if normalized not in _SOURCE_TYPES:
        raise GovernedWorkQueueError('Unsupported governed work source_type.')
    return normalized


def _scope(*, project_id: str, actor_id: str, for_mutation: bool):
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        raise GovernedWorkQueueError('Project is not bound to an active enterprise tenant.')
    organization = Organization.objects.filter(pk=identity['organization_id'], is_active=True).first()
    project = Project.objects.filter(pk=project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).first()
    membership = OrganizationMembership.objects.filter(
        organization_id=identity['organization_id'],
        user_id=actor_id,
        user__is_active=True,
        is_active=True,
    ).first()
    if organization is None or project is None or membership is None:
        raise PermissionError('Active tenant and project membership are required.')
    if for_mutation and membership.role not in MUTATION_ROLES:
        raise PermissionError('Governed work claim mutation requires analyst, manager, admin, or owner authority.')
    return organization, project, membership, identity['id']


def _pending_request_items(organization, project) -> list[dict[str, Any]]:
    rows = (
        GovernedActionRequest.objects.filter(organization=organization, project=project, execution__isnull=True)
        .select_related('requested_by')
        .order_by('created_at', 'id')
    )
    return [{
        'source_type': GovernedWorkClaim.SourceType.GOVERNED_ACTION_REQUEST,
        'source_id': str(row.id),
        'title': f'Governed approval: {row.action_id}',
        'work_category': 'approval',
        'authoritative_state': 'pending_approval',
        'source_version': int(row.expected_version),
        'priority_score': 75,
        'due_at': None,
        'overdue': False,
        'created_at': row.created_at,
        'updated_at': row.created_at,
        'details': {
            'action_id': row.action_id,
            'entity_type': row.entity_type,
            'entity_id': row.entity_id,
            'requested_by_id': str(row.requested_by_id),
            'request_fingerprint': row.request_fingerprint,
            'contract_policy_version': row.contract_policy_version,
            'correlation_id': str(row.correlation_id),
        },
    } for row in rows]


def _decision_action_items(organization, project, now) -> list[dict[str, Any]]:
    terminal = {'verified', 'rejected'}
    rows = (
        DecisionAction.objects.filter(organization=organization, project=project)
        .exclude(state__in=terminal)
        .order_by('created_at', 'action_id')
    )
    items = []
    for row in rows:
        due_at = row.created_at + timedelta(hours=row.sla_hours)
        overdue = due_at <= now or row.sla_status == 'breached'
        priority = max(0, min(100, int(row.priority or 0)))
        if row.sla_status == 'breached':
            priority = 100
        elif row.sla_status == 'at_risk':
            priority = max(priority, 90)
        items.append({
            'source_type': GovernedWorkClaim.SourceType.DECISION_ACTION,
            'source_id': row.action_id,
            'title': row.title,
            'work_category': 'remediation',
            'authoritative_state': row.state,
            'source_version': int(row.version),
            'priority_score': priority,
            'due_at': due_at,
            'overdue': overdue,
            'created_at': row.created_at,
            'updated_at': row.updated_at,
            'details': {
                'owner': row.owner,
                'requested_by': row.requested_by,
                'sla_status': row.sla_status,
                'escalation_level': row.escalation_level,
                'validation_id': str(row.validation_id) if row.validation_id else None,
                'risk_correlation_id': str(row.risk_correlation_id) if row.risk_correlation_id else None,
            },
        })
    return items


def _assurance_items(organization, project, now) -> list[dict[str, Any]]:
    rows = (
        AssuranceObligation.objects.filter(
            organization=organization,
            project=project,
            status__in=[
                AssuranceObligation.Status.OPEN,
                AssuranceObligation.Status.DUE,
                AssuranceObligation.Status.OVERDUE,
            ],
        )
        .order_by('due_at', 'created_at', 'id')
    )
    priority_by_state = {
        AssuranceObligation.Status.OVERDUE: 100,
        AssuranceObligation.Status.DUE: 90,
        AssuranceObligation.Status.OPEN: 60,
    }
    return [{
        'source_type': GovernedWorkClaim.SourceType.ASSURANCE_OBLIGATION,
        'source_id': str(row.id),
        'title': f'Assurance review: {row.kind}',
        'work_category': 'assurance',
        'authoritative_state': row.status,
        'source_version': int(row.version),
        'priority_score': priority_by_state[row.status],
        'due_at': row.due_at,
        'overdue': row.status == AssuranceObligation.Status.OVERDUE or row.due_at <= now,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'details': {
            'finding_id': str(row.finding_id),
            'asset_id': str(row.asset_id),
            'kind': row.kind,
            'generation': row.generation,
            'schedule_id': str(row.schedule_id),
        },
    } for row in rows]


def _investigation_items(organization, project) -> list[dict[str, Any]]:
    rows = (
        InvestigationCase.objects.filter(
            organization=organization,
            project=project,
            status__in=[
                InvestigationCase.Status.OPEN,
                InvestigationCase.Status.INVESTIGATING,
                InvestigationCase.Status.DECIDED,
            ],
        )
        .select_related('owner')
        .order_by('created_at', 'id')
    )
    priority_by_state = {
        InvestigationCase.Status.DECIDED: 85,
        InvestigationCase.Status.INVESTIGATING: 70,
        InvestigationCase.Status.OPEN: 60,
    }
    return [{
        'source_type': GovernedWorkClaim.SourceType.INVESTIGATION_CASE,
        'source_id': str(row.id),
        'title': row.title,
        'work_category': 'investigation',
        'authoritative_state': row.status,
        'source_version': int(getattr(row, 'soc_state').version) if hasattr(row, 'soc_state') else 1,
        'priority_score': priority_by_state[row.status],
        'due_at': None,
        'overdue': False,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'details': {
            'owner_id': str(row.owner_id),
            'decision_summary': row.decision_summary,
        },
    } for row in rows]


def _delivery_items(organization, project) -> list[dict[str, Any]]:
    rows = (
        DetectionPublicationDelivery.objects.filter(
            organization=organization,
            project=project,
            status__in=[
                DetectionPublicationDelivery.Status.FAILED,
                DetectionPublicationDelivery.Status.BLOCKED,
            ],
        )
        .select_related('integration', 'revision__rule')
        .order_by('created_at', 'id')
    )
    priority_by_state = {
        DetectionPublicationDelivery.Status.BLOCKED: 100,
        DetectionPublicationDelivery.Status.FAILED: 95,
    }
    return [{
        'source_type': GovernedWorkClaim.SourceType.DETECTION_DELIVERY,
        'source_id': str(row.id),
        'title': f'Detection delivery: {row.revision.rule.name}',
        'work_category': 'integration_delivery',
        'authoritative_state': row.status,
        'source_version': int(row.attempts) + 1,
        'priority_score': priority_by_state[row.status],
        'due_at': None,
        'overdue': False,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'details': {
            'revision_id': str(row.revision_id),
            'integration_id': str(row.integration_id),
            'integration_kind': row.integration.kind,
            'attempts': row.attempts,
            'last_error': row.last_error,
            'governed_request_id': str(row.governed_request_id),
        },
    } for row in rows]


def _claim_view(claim: GovernedWorkClaim | None, *, actor_id: str, now) -> dict[str, Any]:
    if claim is None:
        return {
            'version': 0,
            'state': 'unclaimed',
            'claimed_by_id': None,
            'claimed_at': None,
            'lease_expires_at': None,
            'mine': False,
        }
    expired = bool(claim.claimed_by_id and claim.lease_expires_at and claim.lease_expires_at <= now)
    state = 'expired' if expired else 'claimed' if claim.claimed_by_id else 'unclaimed'
    return {
        'version': int(claim.version),
        'state': state,
        'claimed_by_id': str(claim.claimed_by_id) if claim.claimed_by_id else None,
        'claimed_at': claim.claimed_at.isoformat() if claim.claimed_at else None,
        'lease_expires_at': claim.lease_expires_at.isoformat() if claim.lease_expires_at else None,
        'mine': bool(claim.claimed_by_id and str(claim.claimed_by_id) == str(actor_id) and not expired),
    }


def _sort_key(item: dict[str, Any]):
    due = item.get('due_at')
    due_sort = due.timestamp() if due is not None else float('inf')
    return (
        -int(item['priority_score']),
        -int(bool(item.get('overdue'))),
        due_sort,
        item['created_at'].timestamp(),
        item['item_key'],
    )


def list_governed_work(
    *,
    actor_id: str,
    project_id: str | None = None,
    source_type: str | None = None,
    claim_state: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    normalized_source = _normalize_source_type(source_type) if source_type else None
    if claim_state not in (None, 'unclaimed', 'claimed', 'expired', 'mine'):
        raise GovernedWorkQueueError('Unsupported claim_state filter.')

    if project_id:
        _scope(project_id=str(project_id), actor_id=str(actor_id), for_mutation=False)
        project_ids = [str(project_id)]
    else:
        org_ids = OrganizationMembership.objects.filter(
            user_id=actor_id, user__is_active=True, is_active=True, organization__is_active=True
        ).values_list('organization_id', flat=True)
        project_ids = list(
            TenantProject.objects.filter(
                organization_id__in=org_ids,
                project__in=Project.objects.filter(Q(owner_id=actor_id) | Q(members__id=actor_id)),
            ).values_list('project_id', flat=True)
        )

    now = timezone.now()
    items: list[dict[str, Any]] = []
    for pid in project_ids:
        organization, project, _membership, _link_id = _scope(
            project_id=str(pid), actor_id=str(actor_id), for_mutation=False
        )
        project_items = [
            *_pending_request_items(organization, project),
            *_decision_action_items(organization, project, now),
            *_assurance_items(organization, project, now),
            *_investigation_items(organization, project),
            *_delivery_items(organization, project),
        ]
        if normalized_source:
            project_items = [item for item in project_items if item['source_type'] == normalized_source]
        claims = {
            (row.source_type, row.source_id): row
            for row in GovernedWorkClaim.objects.filter(organization=organization, project=project)
        }
        for item in project_items:
            item['item_key'] = f"{item['source_type']}:{item['source_id']}"
            item['organization_id'] = str(organization.id)
            item['project_id'] = str(project.id)
            item['claim'] = _claim_view(
                claims.get((item['source_type'], item['source_id'])),
                actor_id=str(actor_id),
                now=now,
            )
            if claim_state == 'mine' and not item['claim']['mine']:
                continue
            if claim_state in {'unclaimed', 'claimed', 'expired'} and item['claim']['state'] != claim_state:
                continue
            items.append(item)

    items.sort(key=_sort_key)
    total = len(items)
    counts: dict[str, int] = {}
    for item in items:
        counts[item['work_category']] = counts.get(item['work_category'], 0) + 1
    items = items[: max(1, min(int(limit), 500))]
    return {
        'policy_version': WORK_QUEUE_POLICY_VERSION,
        'items': items,
        'total': total,
        'returned': len(items),
        'counts': counts,
    }


def _source_snapshot(*, organization, project, source_type: str, source_id: str) -> dict[str, Any]:
    """Resolve and lock exactly one authoritative source before claim mutation."""
    source_type = _normalize_source_type(source_type)
    source_id = str(source_id)
    now = timezone.now()
    item: dict[str, Any] | None = None

    if source_type == GovernedWorkClaim.SourceType.GOVERNED_ACTION_REQUEST:
        row = (
            GovernedActionRequest.objects.select_for_update(of=('self',))
            .select_related('requested_by')
            .filter(
                pk=source_id,
                organization=organization,
                project=project,
                execution__isnull=True,
            )
            .first()
        )
        if row is not None:
            item = {
                'authoritative_state': 'pending_approval',
                'source_version': int(row.expected_version),
                'title': f'Governed approval: {row.action_id}',
                'priority_score': 75,
                'details': {
                    'action_id': row.action_id,
                    'entity_type': row.entity_type,
                    'entity_id': row.entity_id,
                    'requested_by_id': str(row.requested_by_id),
                    'request_fingerprint': row.request_fingerprint,
                    'contract_policy_version': row.contract_policy_version,
                    'correlation_id': str(row.correlation_id),
                },
            }
    elif source_type == GovernedWorkClaim.SourceType.DECISION_ACTION:
        row = (
            DecisionAction.objects.select_for_update(of=('self',))
            .filter(organization=organization, project=project, pk=source_id)
            .exclude(state__in={'verified', 'rejected'})
            .first()
        )
        if row is not None:
            due_at = row.created_at + timedelta(hours=row.sla_hours)
            priority = max(0, min(100, int(row.priority or 0)))
            if row.sla_status == 'breached':
                priority = 100
            elif row.sla_status == 'at_risk':
                priority = max(priority, 90)
            item = {
                'authoritative_state': row.state,
                'source_version': int(row.version),
                'title': row.title,
                'priority_score': priority,
                'details': {
                    'owner': row.owner,
                    'requested_by': row.requested_by,
                    'sla_status': row.sla_status,
                    'escalation_level': row.escalation_level,
                    'validation_id': str(row.validation_id) if row.validation_id else None,
                    'risk_correlation_id': str(row.risk_correlation_id) if row.risk_correlation_id else None,
                    'due_at': due_at.isoformat(),
                    'overdue': bool(due_at <= now or row.sla_status == 'breached'),
                },
            }
    elif source_type == GovernedWorkClaim.SourceType.ASSURANCE_OBLIGATION:
        row = (
            AssuranceObligation.objects.select_for_update(of=('self',))
            .filter(
                pk=source_id,
                organization=organization,
                project=project,
                status__in=[
                    AssuranceObligation.Status.OPEN,
                    AssuranceObligation.Status.DUE,
                    AssuranceObligation.Status.OVERDUE,
                ],
            )
            .first()
        )
        if row is not None:
            priority_by_state = {
                AssuranceObligation.Status.OVERDUE: 100,
                AssuranceObligation.Status.DUE: 90,
                AssuranceObligation.Status.OPEN: 60,
            }
            item = {
                'authoritative_state': row.status,
                'source_version': int(row.version),
                'title': f'Assurance review: {row.kind}',
                'priority_score': priority_by_state[row.status],
                'details': {
                    'finding_id': str(row.finding_id),
                    'asset_id': str(row.asset_id),
                    'kind': row.kind,
                    'generation': row.generation,
                    'schedule_id': str(row.schedule_id),
                    'due_at': row.due_at.isoformat(),
                    'overdue': bool(row.status == AssuranceObligation.Status.OVERDUE or row.due_at <= now),
                },
            }
    elif source_type == GovernedWorkClaim.SourceType.INVESTIGATION_CASE:
        state = (
            InvestigationCaseState.objects.select_for_update(of=('self',))
            .select_related('case__owner')
            .filter(
                case_id=source_id,
                case__organization=organization,
                case__project=project,
                case__status__in=[
                    InvestigationCase.Status.OPEN,
                    InvestigationCase.Status.INVESTIGATING,
                    InvestigationCase.Status.DECIDED,
                ],
            )
            .first()
        )
        if state is not None:
            row = state.case
            priority_by_state = {
                InvestigationCase.Status.DECIDED: 85,
                InvestigationCase.Status.INVESTIGATING: 70,
                InvestigationCase.Status.OPEN: 60,
            }
            item = {
                'authoritative_state': row.status,
                'source_version': int(state.version),
                'title': row.title,
                'priority_score': priority_by_state[row.status],
                'details': {
                    'owner_id': str(row.owner_id),
                    'decision_summary': row.decision_summary,
                    'generation': state.generation,
                },
            }
    elif source_type == GovernedWorkClaim.SourceType.DETECTION_DELIVERY:
        row = (
            DetectionPublicationDelivery.objects.select_for_update(of=('self',))
            .select_related('integration', 'revision__rule')
            .filter(
                pk=source_id,
                organization=organization,
                project=project,
                status__in=[
                    DetectionPublicationDelivery.Status.FAILED,
                    DetectionPublicationDelivery.Status.BLOCKED,
                ],
            )
            .first()
        )
        if row is not None:
            priority_by_state = {
                DetectionPublicationDelivery.Status.BLOCKED: 100,
                DetectionPublicationDelivery.Status.FAILED: 95,
            }
            item = {
                'authoritative_state': row.status,
                'source_version': int(row.attempts) + 1,
                'title': f'Detection delivery: {row.revision.rule.name}',
                'priority_score': priority_by_state[row.status],
                'details': {
                    'revision_id': str(row.revision_id),
                    'integration_id': str(row.integration_id),
                    'integration_kind': row.integration.kind,
                    'attempts': row.attempts,
                    'last_error': row.last_error,
                    'governed_request_id': str(row.governed_request_id),
                },
            }

    if item is None:
        raise GovernedWorkQueueError(
            'Governed work source is no longer actionable or is outside the project scope.'
        )

    return {
        'policy_version': WORK_QUEUE_POLICY_VERSION,
        'source_type': source_type,
        'source_id': source_id,
        'authoritative_state': item['authoritative_state'],
        'source_version': item['source_version'],
        'title': item['title'],
        'priority_score': item['priority_score'],
        'details': item['details'],
        'captured_at': now.isoformat(),
    }


def _event_hash(payload: dict[str, Any]) -> str:
    return _sha(payload)


def _replay_event(*, organization, actor_id: str, key: str, fingerprint: str) -> WorkMutationResult | None:
    event = GovernedWorkClaimEvent.objects.filter(organization=organization, idempotency_key=key).first()
    if event is None:
        return None
    if str(event.actor_id) != str(actor_id) or event.request_fingerprint != fingerprint:
        raise GovernedWorkQueueConflict('Idempotency key was already used for a different governed work mutation.')
    return WorkMutationResult(dict(event.result_snapshot or {}), True)


def mutate_governed_work_claim(
    *,
    actor_id: str,
    project_id: str,
    source_type: str,
    source_id: str,
    operation: str,
    expected_version: int,
    idempotency_key: str,
    lease_seconds: int | None = None,
) -> WorkMutationResult:
    normalized_type = _normalize_source_type(source_type)
    key = _normalize_key(idempotency_key)
    if operation not in {'claim', 'renew', 'release'}:
        raise GovernedWorkQueueError('Unsupported governed work mutation operation.')
    if int(expected_version) < 0:
        raise GovernedWorkQueueError('expected_version must be zero or greater.')
    if operation in {'claim', 'renew'}:
        lease = int(lease_seconds or 0)
        if lease < 60 or lease > 86400:
            raise GovernedWorkQueueError('lease_seconds must be between 60 and 86400.')
    else:
        lease = 0

    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        raise GovernedWorkQueueError('Project is not bound to an active enterprise tenant.')

    fingerprint = _sha({
        'policy_version': WORK_QUEUE_POLICY_VERSION,
        'operation': operation,
        'organization_id': str(identity['organization_id']),
        'project_id': str(project_id),
        'actor_id': str(actor_id),
        'source_type': normalized_type,
        'source_id': str(source_id),
        'expected_version': int(expected_version),
        'lease_seconds': lease,
    })

    with transaction.atomic():
        organization = (
            Organization.objects.select_for_update(of=('self',))
            .filter(pk=identity['organization_id'], is_active=True)
            .first()
        )
        if organization is None:
            raise GovernedWorkQueueError('Project enterprise tenant is not active.')
        link = (
            TenantProject.objects.select_for_update(of=('self',))
            .filter(pk=identity['id'], project_id=project_id, organization=organization)
            .first()
        )
        if link is None:
            raise GovernedWorkQueueError('Project enterprise scope changed while mutating the work queue.')
        project = Project.objects.filter(pk=project_id).filter(
            Q(owner_id=actor_id) | Q(members__id=actor_id)
        ).first()
        membership = OrganizationMembership.objects.filter(
            organization=organization,
            user_id=actor_id,
            user__is_active=True,
            is_active=True,
        ).first()
        if project is None or membership is None:
            raise PermissionError('Active tenant and project membership are required.')
        if membership.role not in MUTATION_ROLES:
            raise PermissionError('Governed work claim mutation requires analyst, manager, admin, or owner authority.')

        replay = _replay_event(
            organization=organization,
            actor_id=str(actor_id),
            key=key,
            fingerprint=fingerprint,
        )
        if replay is not None:
            return replay

        source_snapshot = _source_snapshot(
            organization=organization,
            project=project,
            source_type=normalized_type,
            source_id=str(source_id),
        )

        claim = (
            GovernedWorkClaim.objects.select_for_update()
            .filter(organization=organization, source_type=normalized_type, source_id=str(source_id))
            .first()
        )
        current_version = int(claim.version) if claim is not None else 0
        if current_version != int(expected_version):
            raise StaleGovernedWorkClaimVersion(
                f'Stale governed work claim version: expected {expected_version}, current {current_version}.'
            )

        now = timezone.now()
        active = bool(claim and claim.claimed_by_id and claim.lease_expires_at and claim.lease_expires_at > now)
        previous_claimed_by = str(claim.claimed_by_id) if claim and claim.claimed_by_id else None

        if operation == 'claim':
            if active:
                if str(claim.claimed_by_id) == str(actor_id):
                    raise GovernedWorkQueueConflict('Work item is already actively claimed by this actor; use renew.')
                raise GovernedWorkQueueConflict('Work item is actively claimed by another actor.')
            event_type = (
                GovernedWorkClaimEvent.EventType.RECLAIMED
                if claim is not None and previous_claimed_by is not None
                else GovernedWorkClaimEvent.EventType.CLAIMED
            )
            if claim is None:
                try:
                    claim = GovernedWorkClaim.objects.create(
                        organization=organization,
                        project=project,
                        source_type=normalized_type,
                        source_id=str(source_id),
                        claimed_by_id=actor_id,
                        claimed_at=now,
                        lease_expires_at=now + timedelta(seconds=lease),
                        version=1,
                    )
                except IntegrityError as exc:
                    raise GovernedWorkQueueConflict('Concurrent governed work claim creation conflicted.') from exc
                result_version = 1
            else:
                claim.project = project
                claim.claimed_by_id = actor_id
                claim.claimed_at = now
                claim.lease_expires_at = now + timedelta(seconds=lease)
                claim.version += 1
                claim.save(update_fields=['project','claimed_by','claimed_at','lease_expires_at','version','updated_at'])
                result_version = claim.version
        elif operation == 'renew':
            if not active or str(claim.claimed_by_id) != str(actor_id):
                raise GovernedWorkQueueConflict('Only the active claimant may renew a governed work lease.')
            event_type = GovernedWorkClaimEvent.EventType.RENEWED
            claim.lease_expires_at = now + timedelta(seconds=lease)
            claim.version += 1
            claim.save(update_fields=['lease_expires_at','version','updated_at'])
            result_version = claim.version
        else:
            if not active or str(claim.claimed_by_id) != str(actor_id):
                raise GovernedWorkQueueConflict('Only the active claimant may release a governed work lease.')
            event_type = GovernedWorkClaimEvent.EventType.RELEASED
            claim.claimed_by = None
            claim.claimed_at = None
            claim.lease_expires_at = None
            claim.version += 1
            claim.save(update_fields=['claimed_by','claimed_at','lease_expires_at','version','updated_at'])
            result_version = claim.version

        source_snapshot_sha256 = _sha(source_snapshot)
        result_snapshot = {
            'policy_version': WORK_QUEUE_POLICY_VERSION,
            'source_type': normalized_type,
            'source_id': str(source_id),
            'project_id': str(project.id),
            'organization_id': str(organization.id),
            'operation': operation,
            'claim': _claim_view(claim, actor_id=str(actor_id), now=now),
            'source_snapshot': source_snapshot,
            'source_snapshot_sha256': source_snapshot_sha256,
        }
        previous = (
            GovernedWorkClaimEvent.objects.filter(claim=claim)
            .order_by('-sequence', '-occurred_at', '-id')
            .first()
        )
        previous_hash = previous.entry_hash if previous else ''
        entry_payload = {
            'claim_id': str(claim.id),
            'sequence': result_version,
            'event_type': event_type,
            'actor_id': str(actor_id),
            'idempotency_key': key,
            'request_fingerprint': fingerprint,
            'expected_version': int(expected_version),
            'result_version': result_version,
            'result_claimed_by': str(claim.claimed_by_id) if claim.claimed_by_id else None,
            'lease_expires_at': claim.lease_expires_at.isoformat() if claim.lease_expires_at else None,
            'source_snapshot': source_snapshot,
            'result_snapshot': result_snapshot,
            'previous_hash': previous_hash,
        }
        GovernedWorkClaimEvent.objects.create(
            claim=claim,
            organization=organization,
            project=project,
            sequence=result_version,
            event_type=event_type,
            actor_id=actor_id,
            idempotency_key=key,
            request_fingerprint=fingerprint,
            expected_version=int(expected_version),
            result_version=result_version,
            result_claimed_by=claim.claimed_by,
            lease_expires_at=claim.lease_expires_at,
            source_snapshot=source_snapshot,
            result_snapshot=result_snapshot,
            previous_hash=previous_hash,
            entry_hash=_event_hash(entry_payload),
        )
        return WorkMutationResult(result_snapshot, False)



def verify_governed_work_claim_chain(*, claim_id: str) -> dict[str, Any]:
    claim = GovernedWorkClaim.objects.filter(pk=claim_id).first()
    if claim is None:
        raise GovernedWorkQueueError('Governed work claim was not found.')
    events = list(
        GovernedWorkClaimEvent.objects.filter(claim=claim)
        .order_by('sequence', 'occurred_at', 'id')
    )
    previous_hash = ''
    expected_sequence = 1
    for event in events:
        if event.sequence != expected_sequence or event.result_version != event.sequence:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'sequence_mismatch',
            }
        if event.expected_version != event.sequence - 1:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'version_step_mismatch',
            }
        if event.organization_id != claim.organization_id or event.project_id != claim.project_id:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'scope_mismatch',
            }
        if event.previous_hash != previous_hash:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'previous_hash_mismatch',
            }

        source_snapshot = dict(event.source_snapshot or {})
        result_snapshot = dict(event.result_snapshot or {})
        claim_snapshot = dict(result_snapshot.get('claim') or {})
        if (
            source_snapshot.get('policy_version') != WORK_QUEUE_POLICY_VERSION
            or source_snapshot.get('source_type') != claim.source_type
            or str(source_snapshot.get('source_id')) != str(claim.source_id)
        ):
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'source_snapshot_scope_mismatch',
            }
        if result_snapshot.get('source_snapshot_sha256') != _sha(source_snapshot):
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'source_snapshot_hash_mismatch',
            }
        if (
            result_snapshot.get('policy_version') != WORK_QUEUE_POLICY_VERSION
            or result_snapshot.get('source_type') != claim.source_type
            or str(result_snapshot.get('source_id')) != str(claim.source_id)
            or str(result_snapshot.get('organization_id')) != str(claim.organization_id)
            or str(result_snapshot.get('project_id')) != str(claim.project_id)
            or int(claim_snapshot.get('version', -1)) != event.result_version
        ):
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'result_snapshot_scope_mismatch',
            }
        if claim_snapshot.get('claimed_by_id') != (
            str(event.result_claimed_by_id) if event.result_claimed_by_id else None
        ):
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'result_claimant_mismatch',
            }
        if claim_snapshot.get('lease_expires_at') != (
            event.lease_expires_at.isoformat() if event.lease_expires_at else None
        ):
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'result_lease_mismatch',
            }

        payload = {
            'claim_id': str(claim.id),
            'sequence': event.sequence,
            'event_type': event.event_type,
            'actor_id': str(event.actor_id),
            'idempotency_key': event.idempotency_key,
            'request_fingerprint': event.request_fingerprint,
            'expected_version': event.expected_version,
            'result_version': event.result_version,
            'result_claimed_by': str(event.result_claimed_by_id) if event.result_claimed_by_id else None,
            'lease_expires_at': event.lease_expires_at.isoformat() if event.lease_expires_at else None,
            'source_snapshot': event.source_snapshot,
            'result_snapshot': event.result_snapshot,
            'previous_hash': event.previous_hash,
        }
        calculated = _event_hash(payload)
        if calculated != event.entry_hash:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'entry_hash_mismatch',
            }
        previous_hash = event.entry_hash
        expected_sequence += 1

    if events:
        last = events[-1]
        if claim.version != last.result_version:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'claim_version_mismatch',
            }
        if claim.claimed_by_id != last.result_claimed_by_id:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'claim_owner_mismatch',
            }
        if claim.lease_expires_at != last.lease_expires_at:
            return {
                'valid': False, 'claim_id': str(claim.id), 'events': len(events),
                'reason': 'claim_lease_mismatch',
            }
    return {
        'valid': True,
        'claim_id': str(claim.id),
        'events': len(events),
        'head_hash': previous_hash,
        'version': claim.version,
    }
def verify_governed_work_claim_chain(*, claim_id: str) -> dict[str, Any]:
    claim = GovernedWorkClaim.objects.filter(pk=claim_id).first()
    if claim is None:
        raise GovernedWorkQueueError('Governed work claim was not found.')
    events = list(
        GovernedWorkClaimEvent.objects.filter(claim=claim)
        .order_by('sequence', 'occurred_at', 'id')
    )
    previous_hash = ''
    expected_sequence = 1
    for event in events:
        if event.sequence != expected_sequence or event.result_version != event.sequence:
            return {
                'valid': False,
                'claim_id': str(claim.id),
                'events': len(events),
                'reason': 'sequence_mismatch',
            }
        if event.previous_hash != previous_hash:
            return {
                'valid': False,
                'claim_id': str(claim.id),
                'events': len(events),
                'reason': 'previous_hash_mismatch',
            }
        payload = {
            'claim_id': str(claim.id),
            'sequence': event.sequence,
            'event_type': event.event_type,
            'actor_id': str(event.actor_id),
            'idempotency_key': event.idempotency_key,
            'request_fingerprint': event.request_fingerprint,
            'expected_version': event.expected_version,
            'result_version': event.result_version,
            'result_claimed_by': str(event.result_claimed_by_id) if event.result_claimed_by_id else None,
            'lease_expires_at': event.lease_expires_at.isoformat() if event.lease_expires_at else None,
            'source_snapshot': event.source_snapshot,
            'result_snapshot': event.result_snapshot,
            'previous_hash': event.previous_hash,
        }
        calculated = _event_hash(payload)
        if calculated != event.entry_hash:
            return {
                'valid': False,
                'claim_id': str(claim.id),
                'events': len(events),
                'reason': 'entry_hash_mismatch',
            }
        previous_hash = event.entry_hash
        expected_sequence += 1
    if events and claim.version != events[-1].result_version:
        return {
            'valid': False,
            'claim_id': str(claim.id),
            'events': len(events),
            'reason': 'claim_version_mismatch',
        }
    return {
        'valid': True,
        'claim_id': str(claim.id),
        'events': len(events),
        'head_hash': previous_hash,
        'version': claim.version,
    }
