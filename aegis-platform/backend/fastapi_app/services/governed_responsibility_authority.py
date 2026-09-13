from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from enterprise.governed_responsibility_models import (
    GovernedResponsibilityAssignment,
    GovernedResponsibilityEvent,
    GovernedResponsibilityRevocation,
)
from enterprise.models import Organization, OrganizationMembership, TenantProject


_POLICY_VERSION = 'agom-responsibility.v1'
_ISSUER_ROLES = {OrganizationMembership.Role.OWNER, OrganizationMembership.Role.ADMIN}
_RESPONSIBILITIES = set(GovernedResponsibilityAssignment.Responsibility.values)
_SCOPE_KINDS = set(GovernedResponsibilityAssignment.ScopeKind.values)


class GovernedResponsibilityError(ValueError):
    pass


@dataclass(frozen=True)
class GrantResult:
    assignment: GovernedResponsibilityAssignment
    replayed: bool


@dataclass(frozen=True)
class RevocationResult:
    revocation: GovernedResponsibilityRevocation
    replayed: bool


@dataclass(frozen=True)
class ActorAuthority:
    organization_id: str
    project_id: str | None
    membership_id: str
    role: str
    responsibilities: frozenset[str]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _organization_locked(organization_id: str) -> Organization:
    organization = Organization.objects.select_for_update().filter(pk=organization_id, is_active=True).first()
    if organization is None:
        raise GovernedResponsibilityError('Active organization not found.')
    return organization


def _issuer_locked(organization: Organization, actor_id: str) -> OrganizationMembership:
    membership = (
        OrganizationMembership.objects.select_for_update()
        .filter(
            organization=organization,
            user_id=actor_id,
            is_active=True,
            user__is_active=True,
            role__in=_ISSUER_ROLES,
        )
        .first()
    )
    if membership is None:
        raise PermissionError('Only active organization owner/admin members may govern responsibility assignments.')
    return membership


def _target_membership_locked(organization: Organization, membership_id: str) -> OrganizationMembership:
    membership = (
        OrganizationMembership.objects.select_for_update()
        .select_related('user')
        .filter(pk=membership_id, organization=organization, is_active=True, user__is_active=True)
        .first()
    )
    if membership is None:
        raise GovernedResponsibilityError('Target membership is not active in the organization.')
    return membership


def _project_locked(organization: Organization, project_id: str | None):
    if not project_id:
        return None
    link = (
        TenantProject.objects.select_for_update()
        .select_related('project')
        .filter(organization=organization, project_id=project_id)
        .first()
    )
    if link is None:
        raise GovernedResponsibilityError('Project is outside the organization scope.')
    return link.project


def _normalize_scope(*, scope_kind: str, project_id: str | None, entity_type: str, entity_id: str) -> tuple[str, str | None, str, str]:
    scope = str(scope_kind or '').strip()
    if scope not in _SCOPE_KINDS:
        raise GovernedResponsibilityError('Unsupported responsibility scope kind.')
    project = str(project_id or '').strip() or None
    entity_type = str(entity_type or '').strip().lower()
    entity_id = str(entity_id or '').strip()
    if scope == GovernedResponsibilityAssignment.ScopeKind.ORGANIZATION:
        if project or entity_type or entity_id:
            raise GovernedResponsibilityError('Organization-scoped responsibility cannot carry project/entity scope.')
    elif scope == GovernedResponsibilityAssignment.ScopeKind.PROJECT:
        if not project or entity_type or entity_id:
            raise GovernedResponsibilityError('Project-scoped responsibility requires only project_id.')
    elif scope == GovernedResponsibilityAssignment.ScopeKind.ENTITY_TYPE:
        if not project or not entity_type or entity_id:
            raise GovernedResponsibilityError('Entity-type responsibility requires project_id and entity_type only.')
    elif scope == GovernedResponsibilityAssignment.ScopeKind.ENTITY:
        if not project or not entity_type or not entity_id:
            raise GovernedResponsibilityError('Entity responsibility requires project_id, entity_type and entity_id.')
    return scope, project, entity_type, entity_id


def _append_event_locked(*, organization: Organization, assignment: GovernedResponsibilityAssignment, actor_id: str, event_type: str, payload: dict[str, Any]) -> GovernedResponsibilityEvent:
    previous = GovernedResponsibilityEvent.objects.filter(organization=organization).order_by('-id').first()
    previous_hash = previous.entry_hash if previous else ''
    envelope = {
        'organization_id': str(organization.id),
        'assignment_id': str(assignment.id),
        'event_type': event_type,
        'actor_id': str(actor_id),
        'payload': payload,
        'previous_hash': previous_hash,
    }
    return GovernedResponsibilityEvent.objects.create(
        organization=organization,
        assignment=assignment,
        event_type=event_type,
        actor_id=actor_id,
        payload=payload,
        previous_hash=previous_hash,
        entry_hash=_sha(envelope),
    )


def grant_responsibility(
    *,
    organization_id: str,
    actor_id: str,
    membership_id: str,
    responsibility: str,
    scope_kind: str,
    reason: str,
    project_id: str | None = None,
    entity_type: str = '',
    entity_id: str = '',
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    supersedes_assignment_id: str | None = None,
) -> GrantResult:
    responsibility = str(responsibility or '').strip()
    if responsibility not in _RESPONSIBILITIES:
        raise GovernedResponsibilityError('Unknown governed responsibility.')
    normalized_reason = ' '.join(str(reason or '').split())
    if not normalized_reason:
        raise GovernedResponsibilityError('A governed responsibility grant requires a reason.')
    scope, project_id, entity_type, entity_id = _normalize_scope(
        scope_kind=scope_kind,
        project_id=project_id,
        entity_type=entity_type,
        entity_id=entity_id,
    )
    starts_at = valid_from or timezone.now()
    if timezone.is_naive(starts_at):
        raise GovernedResponsibilityError('valid_from must be timezone-aware.')
    if valid_until is not None:
        if timezone.is_naive(valid_until):
            raise GovernedResponsibilityError('valid_until must be timezone-aware.')
        if valid_until <= starts_at:
            raise GovernedResponsibilityError('valid_until must be later than valid_from.')

    with transaction.atomic():
        organization = _organization_locked(organization_id)
        _issuer_locked(organization, actor_id)
        membership = _target_membership_locked(organization, membership_id)
        project = _project_locked(organization, project_id)

        supersedes = None
        if supersedes_assignment_id:
            supersedes = (
                GovernedResponsibilityAssignment.objects.select_for_update()
                .filter(
                    pk=supersedes_assignment_id,
                    organization=organization,
                    membership=membership,
                    responsibility=responsibility,
                )
                .first()
            )
            if supersedes is None:
                raise GovernedResponsibilityError('Superseded assignment does not match organization, member and responsibility.')
            if hasattr(supersedes, 'superseded_by'):
                raise GovernedResponsibilityError('Responsibility assignment has already been superseded.')
            if hasattr(supersedes, 'revocation'):
                raise GovernedResponsibilityError('Revoked responsibility assignment cannot be superseded.')

        fingerprint_material = {
            'policy_version': _POLICY_VERSION,
            'organization_id': str(organization.id),
            'membership_id': str(membership.id),
            'responsibility': responsibility,
            'scope_kind': scope,
            'project_id': str(project.id) if project else '',
            'entity_type': entity_type,
            'entity_id': entity_id,
            'valid_from': starts_at.isoformat(),
            'valid_until': valid_until.isoformat() if valid_until else '',
            'reason': normalized_reason,
            'issued_by': str(actor_id),
            'supersedes_assignment_id': str(supersedes.id) if supersedes else '',
        }
        fingerprint = _sha(fingerprint_material)
        existing = GovernedResponsibilityAssignment.objects.filter(grant_fingerprint=fingerprint).first()
        if existing is not None:
            return GrantResult(existing, True)

        assignment = GovernedResponsibilityAssignment.objects.create(
            organization=organization,
            project=project,
            membership=membership,
            responsibility=responsibility,
            scope_kind=scope,
            entity_type=entity_type,
            entity_id=entity_id,
            valid_from=starts_at,
            valid_until=valid_until,
            reason=normalized_reason,
            policy_version=_POLICY_VERSION,
            grant_fingerprint=fingerprint,
            issued_by_id=actor_id,
            supersedes=supersedes,
        )
        if supersedes is not None:
            _append_event_locked(
                organization=organization,
                assignment=supersedes,
                actor_id=actor_id,
                event_type=GovernedResponsibilityEvent.EventType.SUPERSEDED,
                payload={'superseded_by_assignment_id': str(assignment.id), 'policy_version': _POLICY_VERSION},
            )
        _append_event_locked(
            organization=organization,
            assignment=assignment,
            actor_id=actor_id,
            event_type=GovernedResponsibilityEvent.EventType.GRANTED,
            payload={**fingerprint_material, 'grant_fingerprint': fingerprint},
        )
        return GrantResult(assignment, False)


def revoke_responsibility(*, assignment_id: str, actor_id: str, reason: str) -> RevocationResult:
    normalized_reason = ' '.join(str(reason or '').split())
    if not normalized_reason:
        raise GovernedResponsibilityError('A responsibility revocation requires a reason.')
    with transaction.atomic():
        assignment = (
            GovernedResponsibilityAssignment.objects.select_for_update()
            .select_related('organization')
            .filter(pk=assignment_id)
            .first()
        )
        if assignment is None:
            raise GovernedResponsibilityError('Governed responsibility assignment not found.')
        organization = _organization_locked(str(assignment.organization_id))
        _issuer_locked(organization, actor_id)
        fingerprint = _sha({
            'policy_version': _POLICY_VERSION,
            'assignment_id': str(assignment.id),
            'reason': normalized_reason,
            'revoked_by': str(actor_id),
        })
        existing = GovernedResponsibilityRevocation.objects.filter(assignment=assignment).first()
        if existing is not None:
            if existing.revocation_fingerprint == fingerprint:
                return RevocationResult(existing, True)
            raise GovernedResponsibilityError('Responsibility assignment has already been revoked with different governance evidence.')
        revocation = GovernedResponsibilityRevocation.objects.create(
            assignment=assignment,
            reason=normalized_reason,
            policy_version=_POLICY_VERSION,
            revocation_fingerprint=fingerprint,
            revoked_by_id=actor_id,
        )
        _append_event_locked(
            organization=organization,
            assignment=assignment,
            actor_id=actor_id,
            event_type=GovernedResponsibilityEvent.EventType.REVOKED,
            payload={
                'revocation_id': str(revocation.id),
                'reason': normalized_reason,
                'policy_version': _POLICY_VERSION,
                'revocation_fingerprint': fingerprint,
            },
        )
        return RevocationResult(revocation, False)


def resolve_actor_authority(
    *,
    organization_id: str,
    user_id: str,
    project_id: str | None = None,
    entity_type: str = '',
    entity_id: str = '',
    at: datetime | None = None,
) -> ActorAuthority:
    now = at or timezone.now()
    if timezone.is_naive(now):
        raise GovernedResponsibilityError('Authority evaluation time must be timezone-aware.')
    organization = Organization.objects.filter(pk=organization_id, is_active=True).first()
    if organization is None:
        raise GovernedResponsibilityError('Active organization not found.')
    membership = (
        OrganizationMembership.objects.select_related('user')
        .filter(organization=organization, user_id=user_id, is_active=True, user__is_active=True)
        .first()
    )
    if membership is None:
        raise PermissionError('Active organization membership is required.')
    project = None
    if project_id:
        link = TenantProject.objects.select_related('project').filter(organization=organization, project_id=project_id).first()
        if link is None:
            raise GovernedResponsibilityError('Project is outside the organization scope.')
        project = link.project

    entity_type = str(entity_type or '').strip().lower()
    entity_id = str(entity_id or '').strip()
    if entity_id and not entity_type:
        raise GovernedResponsibilityError('entity_id requires entity_type.')
    if entity_type and project is None:
        raise GovernedResponsibilityError('Entity-scoped authority resolution requires project_id.')

    scope_filter = Q(scope_kind=GovernedResponsibilityAssignment.ScopeKind.ORGANIZATION)
    if project is not None:
        scope_filter |= Q(scope_kind=GovernedResponsibilityAssignment.ScopeKind.PROJECT, project=project)
        if entity_type:
            scope_filter |= Q(
                scope_kind=GovernedResponsibilityAssignment.ScopeKind.ENTITY_TYPE,
                project=project,
                entity_type=entity_type,
            )
            if entity_id:
                scope_filter |= Q(
                    scope_kind=GovernedResponsibilityAssignment.ScopeKind.ENTITY,
                    project=project,
                    entity_type=entity_type,
                    entity_id=entity_id,
                )

    assignments = (
        GovernedResponsibilityAssignment.objects.filter(
            organization=organization,
            membership=membership,
            valid_from__lte=now,
        )
        .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=now))
        .filter(scope_filter)
        .filter(revocation__isnull=True, superseded_by__isnull=True)
        .values_list('responsibility', flat=True)
    )
    return ActorAuthority(
        organization_id=str(organization.id),
        project_id=str(project.id) if project else None,
        membership_id=str(membership.id),
        role=membership.role,
        responsibilities=frozenset(assignments),
    )


def verify_responsibility_event_chain(*, organization_id: str) -> dict[str, Any]:
    organization = Organization.objects.filter(pk=organization_id).first()
    if organization is None:
        raise GovernedResponsibilityError('Organization not found.')
    previous = ''
    rows = list(GovernedResponsibilityEvent.objects.filter(organization=organization).order_by('id'))
    for row in rows:
        if row.previous_hash != previous:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'previous_hash'}
        envelope = {
            'organization_id': str(organization.id),
            'assignment_id': str(row.assignment_id),
            'event_type': row.event_type,
            'actor_id': str(row.actor_id),
            'payload': row.payload,
            'previous_hash': row.previous_hash,
        }
        expected = _sha(envelope)
        if row.entry_hash != expected:
            return {'valid': False, 'entries': len(rows), 'broken_at': row.id, 'reason': 'entry_hash'}
        previous = row.entry_hash
    return {'valid': True, 'entries': len(rows), 'head': previous}
