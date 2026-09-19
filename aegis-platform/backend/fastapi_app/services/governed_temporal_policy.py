from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Iterable

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from enterprise.governed_temporal_models import (
    GovernedTemporalEvaluation,
    GovernedTemporalException,
    GovernedTemporalExceptionRevocation,
)
from enterprise.models import Organization, OrganizationMembership, TenantProject


POLICY_VERSION = 'agom-temporal.v1'
ISSUER_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
}
HARD_BLOCKS = frozenset({
    'tenant_authority',
    'separation_of_duties',
    'revoked_evidence',
    'expired_authorization',
    'immutable_security_control',
})


class GovernedTemporalError(ValueError):
    pass


class GovernedTemporalConflict(GovernedTemporalError):
    pass


@dataclass(frozen=True)
class TemporalEnvelope:
    effective_from: datetime | None = None
    expires_at: datetime | None = None
    review_at: datetime | None = None
    grace_period_seconds: int = 0
    renewal_ref: str = ''
    recurrence: dict[str, Any] | None = None
    escalation_level: int = 0

    def snapshot(self) -> dict[str, Any]:
        return {
            'effective_from': _iso(self.effective_from),
            'expires_at': _iso(self.expires_at),
            'review_at': _iso(self.review_at),
            'grace_period_seconds': int(self.grace_period_seconds),
            'renewal_ref': str(self.renewal_ref or ''),
            'recurrence': dict(self.recurrence or {}),
            'escalation_level': int(self.escalation_level),
        }


@dataclass(frozen=True)
class TemporalEvaluationResult:
    evaluation: GovernedTemporalEvaluation
    replayed: bool

    @property
    def allowed(self) -> bool:
        return bool(self.evaluation.allowed)


@dataclass(frozen=True)
class DeadlineClassification:
    state: str
    remaining_seconds: int
    escalation_level: int


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware(value).isoformat()


def _aware(value: datetime) -> datetime:
    if timezone.is_naive(value):
        return timezone.make_aware(value, dt_timezone.utc)
    return value


def _normalized_reason(value: str) -> str:
    reason = ' '.join(str(value or '').split())
    if len(reason) < 3:
        raise GovernedTemporalError('A reason of at least 3 characters is required.')
    return reason


def _idempotency_key(value: str) -> str:
    key = str(value or '').strip()
    if not key:
        raise GovernedTemporalError('A non-empty idempotency_key is required.')
    if len(key) > 128:
        raise GovernedTemporalError('idempotency_key exceeds 128 characters.')
    return key


def validate_review_deadline(
    review_at: datetime | None,
    *,
    now: datetime | None = None,
    max_horizon: timedelta | None = None,
) -> datetime:
    if review_at is None:
        raise GovernedTemporalError('review_at is required.')
    value = _aware(review_at)
    current = _aware(now or timezone.now())
    if value <= current:
        raise GovernedTemporalError('review_at must be in the future.')
    if max_horizon is not None and value > current + max_horizon:
        raise GovernedTemporalError('review_at exceeds the maximum policy horizon.')
    return value


def classify_deadline(
    *,
    due_at: datetime,
    now: datetime | None = None,
    warning_window: timedelta | None = None,
    grace_period: timedelta | None = None,
) -> DeadlineClassification:
    due = _aware(due_at)
    current = _aware(now or timezone.now())
    warning = warning_window or timedelta(0)
    grace = grace_period or timedelta(0)
    remaining = int((due - current).total_seconds())
    if current >= due + grace:
        return DeadlineClassification('overdue', remaining, 2)
    if current >= due:
        if grace.total_seconds() > 0:
            return DeadlineClassification('grace', remaining, 1)
        return DeadlineClassification('overdue', remaining, 2)
    if due <= current + warning:
        return DeadlineClassification('due', remaining, 1)
    return DeadlineClassification('open', remaining, 0)


def classify_sla(
    *,
    started_at: datetime,
    sla_seconds: int,
    now: datetime | None = None,
    at_risk_ratio: float = 0.2,
) -> DeadlineClassification:
    if int(sla_seconds) <= 0:
        raise GovernedTemporalError('sla_seconds must be positive.')
    current = _aware(now or timezone.now())
    due_at = _aware(started_at) + timedelta(seconds=int(sla_seconds))
    remaining = int((due_at - current).total_seconds())
    ratio = remaining / max(1, int(sla_seconds))
    if remaining <= 0:
        return DeadlineClassification('breached', remaining, 2)
    if ratio <= float(at_risk_ratio):
        return DeadlineClassification('at_risk', remaining, 1)
    return DeadlineClassification('on_track', remaining, 0)


def _scope_match(
    item: GovernedTemporalException,
    *,
    action_id: str,
    entity_type: str,
    entity_id: str,
) -> bool:
    if item.scope_kind == GovernedTemporalException.ScopeKind.PROJECT:
        return True
    if item.scope_kind == GovernedTemporalException.ScopeKind.ENTITY_TYPE:
        return item.entity_type == entity_type
    if item.scope_kind == GovernedTemporalException.ScopeKind.ENTITY:
        return item.entity_type == entity_type and item.entity_id == entity_id
    if item.scope_kind == GovernedTemporalException.ScopeKind.ACTION:
        if item.action_id != action_id:
            return False
        if item.entity_type and item.entity_type != entity_type:
            return False
        if item.entity_id and item.entity_id != entity_id:
            return False
        return True
    return False


def _scope_specificity(item: GovernedTemporalException) -> int:
    return {
        GovernedTemporalException.ScopeKind.PROJECT: 1,
        GovernedTemporalException.ScopeKind.ENTITY_TYPE: 2,
        GovernedTemporalException.ScopeKind.ENTITY: 3,
        GovernedTemporalException.ScopeKind.ACTION: 4,
    }.get(item.scope_kind, 0)


def _select_exception_locked(
    *,
    organization: Organization,
    project_id: str,
    action_id: str,
    entity_type: str,
    entity_id: str,
    evaluated_at: datetime,
) -> GovernedTemporalException | None:
    candidates = list(
        GovernedTemporalException.objects.select_for_update(of=('self',))
        .filter(
            organization=organization,
            project_id=project_id,
            effective_from__lte=evaluated_at,
            expires_at__gt=evaluated_at,
            revocation__isnull=True,
            superseded_by__isnull=True,
        )
        .filter(Q(review_at__isnull=True) | Q(review_at__gt=evaluated_at))
        .order_by('-issued_at', '-id')
    )
    matching = [
        item for item in candidates
        if _scope_match(
            item,
            action_id=action_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
    ]
    matching.sort(key=lambda item: (_scope_specificity(item), item.issued_at, str(item.id)), reverse=True)
    return matching[0] if matching else None


def _base_decision(
    *,
    envelope: TemporalEnvelope,
    evaluated_at: datetime,
) -> tuple[str, bool, list[str], list[str], int]:
    reasons: list[str] = []
    codes: list[str] = []
    escalation = int(envelope.escalation_level)

    effective_from = _aware(envelope.effective_from) if envelope.effective_from else None
    expires_at = _aware(envelope.expires_at) if envelope.expires_at else None
    review_at = _aware(envelope.review_at) if envelope.review_at else None
    grace = timedelta(seconds=max(0, int(envelope.grace_period_seconds)))

    if effective_from and evaluated_at < effective_from:
        codes.append('NOT_YET_EFFECTIVE')
        reasons.append('The governed temporal envelope is not yet effective.')
        return GovernedTemporalEvaluation.Decision.NOT_YET_EFFECTIVE, False, codes, reasons, escalation

    if expires_at and evaluated_at >= expires_at:
        if grace.total_seconds() > 0 and evaluated_at < expires_at + grace:
            codes.append('GRACE_ACTIVE')
            reasons.append('The primary temporal window expired, but the explicit grace period remains active.')
            escalation = max(escalation, 1)
            return GovernedTemporalEvaluation.Decision.GRACE_ACTIVE, True, codes, reasons, escalation
        codes.append('EXPIRED')
        reasons.append('The governed temporal envelope has expired.')
        escalation = max(escalation, 2)
        return GovernedTemporalEvaluation.Decision.EXPIRED, False, codes, reasons, escalation

    if review_at and evaluated_at >= review_at:
        codes.append('REVIEW_DUE')
        reasons.append('The governed temporal envelope requires review before sensitive mutation.')
        escalation = max(escalation, 1)
        return GovernedTemporalEvaluation.Decision.REVIEW_DUE, False, codes, reasons, escalation

    return GovernedTemporalEvaluation.Decision.ACTIVE, True, ['ACTIVE'], ['Temporal policy is active.'], escalation


def evaluate_governed_temporal_policy(
    *,
    project_id: str,
    action_id: str,
    entity_type: str,
    entity_id: str,
    requested_by_id: str | None = None,
    envelope: TemporalEnvelope | None = None,
    hard_blocks: Iterable[str] = (),
    evaluated_at: datetime | None = None,
) -> TemporalEvaluationResult:
    project_id = str(project_id or '').strip()
    action_id = str(action_id or '').strip()
    entity_type = str(entity_type or '').strip().lower()
    entity_id = str(entity_id or '').strip()
    if not all((project_id, action_id, entity_type, entity_id)):
        raise GovernedTemporalError('project_id, action_id, entity_type, and entity_id are required.')

    current = _aware(evaluated_at or timezone.now())
    envelope = envelope or TemporalEnvelope()
    derived_blocks = {
        str(item or '').strip().lower()
        for item in hard_blocks
        if str(item or '').strip()
    }
    recurrence = dict(envelope.recurrence or {})
    if (
        recurrence.get('source') == 'asset_authorization'
        and envelope.expires_at is not None
        and current >= _aware(envelope.expires_at)
    ):
        derived_blocks.add('expired_authorization')
    normalized_blocks = sorted(derived_blocks)
    unknown_blocks = sorted(set(normalized_blocks) - HARD_BLOCKS)
    if unknown_blocks:
        raise GovernedTemporalError(f'Unknown hard block(s): {unknown_blocks}.')

    with transaction.atomic():
        identity = (
            TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
            .values('id', 'organization_id')
            .first()
        )
        if identity is None:
            raise GovernedTemporalError('Project is not bound to an active enterprise tenant.')
        organization = (
            Organization.objects.select_for_update(of=('self',))
            .filter(pk=identity['organization_id'], is_active=True)
            .first()
        )
        if organization is None:
            raise GovernedTemporalError('Project enterprise tenant is not active.')
        link = (
            TenantProject.objects.select_for_update(of=('self',))
            .select_related('project')
            .filter(pk=identity['id'], project_id=project_id, organization=organization)
            .first()
        )
        if link is None:
            raise GovernedTemporalError('Project enterprise scope changed during temporal evaluation.')
        if requested_by_id:
            membership_exists = OrganizationMembership.objects.filter(
                organization=organization,
                user_id=requested_by_id,
                is_active=True,
                user__is_active=True,
            ).exists()
            if not membership_exists:
                raise PermissionError('Active tenant membership is required for governed temporal evaluation.')

        selected = _select_exception_locked(
            organization=organization,
            project_id=project_id,
            action_id=action_id,
            entity_type=entity_type,
            entity_id=entity_id,
            evaluated_at=current,
        )

        if normalized_blocks:
            decision = GovernedTemporalEvaluation.Decision.HARD_BLOCKED
            allowed = False
            reason_codes = [f'HARD_BLOCK:{item}' for item in normalized_blocks]
            reasons = ['A temporal exception/waiver cannot override a protected security boundary.']
            escalation = max(int(envelope.escalation_level), 2)
            selected = None
        else:
            decision, allowed, reason_codes, reasons, escalation = _base_decision(
                envelope=envelope,
                evaluated_at=current,
            )
            if not allowed and selected is not None and decision in {
                GovernedTemporalEvaluation.Decision.EXPIRED,
                GovernedTemporalEvaluation.Decision.REVIEW_DUE,
            }:
                decision = (
                    GovernedTemporalEvaluation.Decision.WAIVER_ACTIVE
                    if selected.kind == GovernedTemporalException.Kind.WAIVER
                    else GovernedTemporalEvaluation.Decision.EXCEPTION_ACTIVE
                )
                allowed = True
                reason_codes = [
                    'WAIVER_ACTIVE' if selected.kind == GovernedTemporalException.Kind.WAIVER else 'EXCEPTION_ACTIVE'
                ]
                reasons = [
                    'An explicit, current, scoped temporal exception permits this otherwise time-blocked operation.'
                ]
                escalation = max(escalation, int(selected.escalation_level))

        policy_snapshot = {
            'policy_version': POLICY_VERSION,
            'hard_blocks_non_overridable': sorted(HARD_BLOCKS),
            'exception_precedence': ['action', 'entity', 'entity_type', 'project'],
            'exception_override_decisions': ['expired', 'review_due'],
            'grace_requires_explicit_seconds': True,
        }
        context = {
            'organization_id': str(organization.id),
            'project_id': project_id,
            'action_id': action_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'requested_by_id': str(requested_by_id or ''),
            'evaluated_at': current.isoformat(),
            'envelope': envelope.snapshot(),
            'hard_blocks': normalized_blocks,
            'selected_exception_id': str(selected.id) if selected else '',
        }
        fingerprint = _sha({'policy': policy_snapshot, 'context': context, 'decision': decision})
        evaluation, created = GovernedTemporalEvaluation.objects.get_or_create(
            evaluation_fingerprint=fingerprint,
            defaults={
                'organization': organization,
                'project': link.project,
                'requested_by_id': requested_by_id or None,
                'action_id': action_id,
                'entity_type': entity_type,
                'entity_id': entity_id,
                'effective_from': _aware(envelope.effective_from) if envelope.effective_from else None,
                'expires_at': _aware(envelope.expires_at) if envelope.expires_at else None,
                'review_at': _aware(envelope.review_at) if envelope.review_at else None,
                'grace_period_seconds': max(0, int(envelope.grace_period_seconds)),
                'renewal_ref': str(envelope.renewal_ref or ''),
                'recurrence': dict(envelope.recurrence or {}),
                'escalation_level': escalation,
                'exception': selected,
                'decision': decision,
                'allowed': allowed,
                'reason_codes': reason_codes,
                'reasons': reasons,
                'hard_blocks': normalized_blocks,
                'policy_version': POLICY_VERSION,
                'policy_snapshot': policy_snapshot,
                'evaluation_context': context,
                'evaluated_at': current,
            },
        )
        return TemporalEvaluationResult(evaluation=evaluation, replayed=not created)


def _issuer_locked(organization: Organization, actor_id: str) -> OrganizationMembership:
    membership = (
        OrganizationMembership.objects.select_for_update(of=('self',))
        .filter(
            organization=organization,
            user_id=actor_id,
            is_active=True,
            user__is_active=True,
            role__in=ISSUER_ROLES,
        )
        .first()
    )
    if membership is None:
        raise PermissionError('Only active organization owner/admin members may issue temporal exceptions.')
    return membership


def issue_temporal_exception(
    *,
    project_id: str,
    actor_id: str,
    kind: str,
    scope_kind: str,
    effective_from: datetime,
    expires_at: datetime,
    reason: str,
    idempotency_key: str,
    action_id: str = '',
    entity_type: str = '',
    entity_id: str = '',
    review_at: datetime | None = None,
    grace_period_seconds: int = 0,
    escalation_level: int = 0,
    recurrence: dict[str, Any] | None = None,
    renewal_of_id: str | None = None,
    supersedes_id: str | None = None,
) -> tuple[GovernedTemporalException, bool]:
    project_id = str(project_id or '').strip()
    actor_id = str(actor_id or '').strip()
    kind = str(kind or '').strip()
    scope_kind = str(scope_kind or '').strip()
    action_id = str(action_id or '').strip()
    entity_type = str(entity_type or '').strip().lower()
    entity_id = str(entity_id or '').strip()
    key = _idempotency_key(idempotency_key)
    normalized_reason = _normalized_reason(reason)
    start = _aware(effective_from)
    end = _aware(expires_at)
    review = _aware(review_at) if review_at else None
    if kind not in GovernedTemporalException.Kind.values:
        raise GovernedTemporalError('Unsupported temporal exception kind.')
    if scope_kind not in GovernedTemporalException.ScopeKind.values:
        raise GovernedTemporalError('Unsupported temporal exception scope.')
    if end <= start:
        raise GovernedTemporalError('expires_at must be after effective_from.')
    if review is not None and not (start < review < end):
        raise GovernedTemporalError('review_at must be inside the temporal exception validity window.')
    if renewal_of_id and supersedes_id:
        raise GovernedTemporalError('A temporal exception cannot be both renewal_of and supersedes in one record.')

    if scope_kind == GovernedTemporalException.ScopeKind.PROJECT:
        if action_id or entity_type or entity_id:
            raise GovernedTemporalError('Project temporal scope cannot carry action/entity selectors.')
    elif scope_kind == GovernedTemporalException.ScopeKind.ENTITY_TYPE:
        if action_id or not entity_type or entity_id:
            raise GovernedTemporalError('Entity-type temporal scope requires only entity_type.')
    elif scope_kind == GovernedTemporalException.ScopeKind.ENTITY:
        if action_id or not entity_type or not entity_id:
            raise GovernedTemporalError('Entity temporal scope requires entity_type and entity_id.')
    elif scope_kind == GovernedTemporalException.ScopeKind.ACTION:
        if not action_id:
            raise GovernedTemporalError('Action temporal scope requires action_id.')
        if entity_id and not entity_type:
            raise GovernedTemporalError('Action temporal scope cannot bind entity_id without entity_type.')

    request_material = {
        'policy_version': POLICY_VERSION,
        'project_id': project_id,
        'actor_id': actor_id,
        'kind': kind,
        'scope_kind': scope_kind,
        'action_id': action_id,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'effective_from': start.isoformat(),
        'expires_at': end.isoformat(),
        'review_at': review.isoformat() if review else '',
        'grace_period_seconds': max(0, int(grace_period_seconds)),
        'escalation_level': max(0, int(escalation_level)),
        'recurrence': dict(recurrence or {}),
        'renewal_of_id': str(renewal_of_id or ''),
        'supersedes_id': str(supersedes_id or ''),
        'reason': normalized_reason,
        'idempotency_key': key,
    }
    request_fingerprint = _sha(request_material)

    with transaction.atomic():
        identity = (
            TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
            .values('id', 'organization_id')
            .first()
        )
        if identity is None:
            raise GovernedTemporalError('Project is not bound to an active enterprise tenant.')
        organization = Organization.objects.select_for_update(of=('self',)).get(pk=identity['organization_id'])
        link = TenantProject.objects.select_for_update(of=('self',)).select_related('project').get(
            pk=identity['id'],
            organization=organization,
            project_id=project_id,
        )
        _issuer_locked(organization, actor_id)

        replay = GovernedTemporalException.objects.filter(
            organization=organization,
            idempotency_key=key,
        ).first()
        if replay is not None:
            if replay.request_fingerprint != request_fingerprint:
                raise GovernedTemporalConflict(
                    'Temporal exception idempotency key was used for a different request.'
                )
            return replay, True

        renewal = None
        supersedes = None

        def _require_compatible_lineage(parent: GovernedTemporalException, label: str) -> None:
            expected = (kind, scope_kind, action_id, entity_type, entity_id)
            actual = (
                parent.kind,
                parent.scope_kind,
                parent.action_id,
                parent.entity_type,
                parent.entity_id,
            )
            if actual != expected:
                raise GovernedTemporalError(
                    f'{label} temporal exception must preserve kind and exact scope semantics.'
                )
            if hasattr(parent, 'revocation'):
                raise GovernedTemporalError(f'{label} temporal exception is revoked and cannot be reused.')
            if hasattr(parent, 'superseded_by'):
                raise GovernedTemporalError(f'{label} temporal exception has already been superseded.')

        def _current_renewal_ids(parent: GovernedTemporalException) -> list:
            child_ids = list(
                GovernedTemporalException.objects.filter(renewal_of=parent)
                .values_list('id', flat=True)
            )
            if not child_ids:
                return []
            revoked_child_ids = set(
                GovernedTemporalExceptionRevocation.objects.filter(
                    exception_id__in=child_ids,
                ).values_list('exception_id', flat=True)
            )
            superseded_child_ids = set(
                GovernedTemporalException.objects.filter(
                    supersedes_id__in=child_ids,
                ).values_list('supersedes_id', flat=True)
            )
            return [
                child_id for child_id in child_ids
                if child_id not in revoked_child_ids and child_id not in superseded_child_ids
            ]

        if renewal_of_id:
            renewal = GovernedTemporalException.objects.select_for_update(of=('self',)).filter(
                pk=renewal_of_id,
                organization=organization,
                project=link.project,
            ).first()
            if renewal is None:
                raise GovernedTemporalError('renewal_of temporal exception is outside tenant/project scope.')
            _require_compatible_lineage(renewal, 'renewal_of')
            # Organization + renewal parent are already row-locked above, which
            # serializes concurrent renewal issuance. Avoid SELECT FOR UPDATE
            # across nullable reverse OneToOne joins (unsupported by PostgreSQL).
            if _current_renewal_ids(renewal):
                raise GovernedTemporalConflict('renewal_of temporal exception already has a current renewal.')
        if supersedes_id:
            supersedes = GovernedTemporalException.objects.select_for_update(of=('self',)).filter(
                pk=supersedes_id,
                organization=organization,
                project=link.project,
            ).first()
            if supersedes is None:
                raise GovernedTemporalError('supersedes temporal exception is outside tenant/project scope.')
            _require_compatible_lineage(supersedes, 'supersedes')
            if _current_renewal_ids(supersedes):
                raise GovernedTemporalConflict(
                    'supersedes temporal exception has a current renewal; supersede the current renewal leaf instead.'
                )

        grant_fingerprint = _sha({
            **request_material,
            'organization_id': str(organization.id),
            'renewal_of': str(renewal.id) if renewal else '',
            'supersedes': str(supersedes.id) if supersedes else '',
        })
        item = GovernedTemporalException.objects.create(
            organization=organization,
            project=link.project,
            kind=kind,
            scope_kind=scope_kind,
            action_id=action_id,
            entity_type=entity_type,
            entity_id=entity_id,
            effective_from=start,
            expires_at=end,
            review_at=review,
            grace_period_seconds=max(0, int(grace_period_seconds)),
            escalation_level=max(0, int(escalation_level)),
            recurrence=dict(recurrence or {}),
            reason=normalized_reason,
            policy_version=POLICY_VERSION,
            idempotency_key=key,
            request_fingerprint=request_fingerprint,
            grant_fingerprint=grant_fingerprint,
            renewal_of=renewal,
            supersedes=supersedes,
            issued_by_id=actor_id,
        )
        return item, False


def revoke_temporal_exception(
    *,
    exception_id: str,
    actor_id: str,
    reason: str,
    idempotency_key: str,
) -> tuple[GovernedTemporalExceptionRevocation, bool]:
    key = _idempotency_key(idempotency_key)
    normalized_reason = _normalized_reason(reason)
    with transaction.atomic():
        identity = (
            GovernedTemporalException.objects.filter(pk=exception_id)
            .values('organization_id')
            .first()
        )
        if identity is None:
            raise GovernedTemporalError('Temporal exception was not found.')
        organization = Organization.objects.select_for_update(of=('self',)).get(pk=identity['organization_id'])
        _issuer_locked(organization, actor_id)
        exception = (
            GovernedTemporalException.objects.select_for_update(of=('self',))
            .filter(pk=exception_id, organization=organization)
            .first()
        )
        if exception is None:
            raise GovernedTemporalError('Temporal exception was not found in the issuer tenant.')

        request_fingerprint = _sha({
            'policy_version': POLICY_VERSION,
            'exception_id': str(exception.id),
            'organization_id': str(organization.id),
            'actor_id': str(actor_id),
            'reason': normalized_reason,
            'idempotency_key': key,
        })
        replay = GovernedTemporalExceptionRevocation.objects.filter(
            organization=organization,
            idempotency_key=key,
        ).first()
        if replay is not None:
            if replay.request_fingerprint != request_fingerprint:
                raise GovernedTemporalConflict(
                    'Temporal exception revocation idempotency key was used for a different request.'
                )
            return replay, True
        if hasattr(exception, 'revocation'):
            raise GovernedTemporalConflict('Temporal exception is already revoked.')

        revocation = GovernedTemporalExceptionRevocation.objects.create(
            organization=organization,
            exception=exception,
            reason=normalized_reason,
            idempotency_key=key,
            request_fingerprint=request_fingerprint,
            revocation_fingerprint=_sha({
                'exception_id': str(exception.id),
                'request_fingerprint': request_fingerprint,
            }),
            revoked_by_id=actor_id,
        )
        return revocation, False
