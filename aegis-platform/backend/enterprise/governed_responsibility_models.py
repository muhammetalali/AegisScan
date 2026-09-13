from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.utils import timezone

from .models import Organization, OrganizationMembership


class _ImmutableGovernanceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Governed responsibility records are immutable; append a new governance record instead.')

    def delete(self):
        raise ValidationError('Governed responsibility records are immutable and cannot be deleted.')


class GovernedResponsibilityAssignment(models.Model):
    """Immutable, idempotent grant of an AGOM responsibility to an organization member."""

    class Responsibility(models.TextChoices):
        AUTHORIZATION_APPROVER = 'authorization_approver', 'Authorization Approver'
        FINDING_CONFIRMER = 'finding_confirmer', 'Finding Confirmer'
        RISK_APPROVER = 'risk_approver', 'Risk Approver'
        CLOSURE_APPROVER = 'closure_approver', 'Closure Approver'
        CAMPAIGN_ASSESSOR = 'campaign_assessor', 'Campaign Assessor'
        CAMPAIGN_LEAD = 'campaign_lead', 'Campaign Lead'
        DETECTION_PUBLISHER = 'detection_publisher', 'Detection Publisher'
        SOC_CLOSURE_APPROVER = 'soc_closure_approver', 'SOC Closure Approver'
        ASSURANCE_OWNER = 'assurance_owner', 'Assurance Owner'
        INTEGRATION_ACCEPTOR = 'integration_acceptor', 'Integration Acceptor'

    class ScopeKind(models.TextChoices):
        ORGANIZATION = 'organization', 'Organization'
        PROJECT = 'project', 'Project'
        ENTITY_TYPE = 'entity_type', 'Entity Type'
        ENTITY = 'entity', 'Entity'

    objects = _ImmutableGovernanceQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name='governed_responsibility_assignments',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='governed_responsibility_assignments',
    )
    membership = models.ForeignKey(
        OrganizationMembership,
        on_delete=models.PROTECT,
        related_name='governed_responsibility_assignments',
    )
    responsibility = models.CharField(max_length=64, choices=Responsibility.choices)
    scope_kind = models.CharField(max_length=24, choices=ScopeKind.choices)
    entity_type = models.CharField(max_length=80, blank=True)
    entity_id = models.CharField(max_length=128, blank=True)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_until = models.DateTimeField(null=True, blank=True)
    reason = models.TextField()
    policy_version = models.CharField(max_length=64, default='agom-responsibility.v1')
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    grant_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='issued_governed_responsibilities',
    )
    issued_at = models.DateTimeField(auto_now_add=True)
    supersedes = models.OneToOneField(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='superseded_by',
    )

    class Meta:
        ordering = ['-issued_at', '-id']
        indexes = [
            models.Index(fields=['organization', 'membership', 'responsibility'], name='idx_govresp_org_member'),
            models.Index(fields=['project', 'entity_type'], name='idx_govresp_project_entity'),
            models.Index(fields=['valid_until'], name='idx_govresp_valid_until'),
        ]
        constraints = [
            models.UniqueConstraint(fields=['organization', 'idempotency_key'], name='uniq_govresp_grant_idem'),
            models.CheckConstraint(
                condition=Q(valid_until__isnull=True) | Q(valid_until__gt=models.F('valid_from')),
                name='govresp_valid_window',
            ),
            models.CheckConstraint(
                condition=(
                    Q(scope_kind='organization', project__isnull=True, entity_type='', entity_id='')
                    | Q(scope_kind='project', project__isnull=False, entity_type='', entity_id='')
                    | (Q(scope_kind='entity_type', project__isnull=False, entity_id='') & ~Q(entity_type=''))
                    | (Q(scope_kind='entity', project__isnull=False) & ~Q(entity_type='') & ~Q(entity_id=''))
                ),
                name='govresp_scope_shape',
            ),
        ]

    @property
    def is_currently_valid(self) -> bool:
        now = timezone.now()
        if self.valid_from > now:
            return False
        if self.valid_until is not None and self.valid_until <= now:
            return False
        if hasattr(self, 'revocation'):
            return False
        if hasattr(self, 'superseded_by'):
            return False
        return True

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed responsibility assignments are immutable; create a superseding grant.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed responsibility assignments are immutable and cannot be deleted.')


class GovernedResponsibilityRevocation(models.Model):
    """Immutable, idempotent revocation record; assignments themselves are never edited."""

    objects = _ImmutableGovernanceQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name='governed_responsibility_revocations',
    )
    assignment = models.OneToOneField(
        GovernedResponsibilityAssignment,
        on_delete=models.PROTECT,
        related_name='revocation',
    )
    reason = models.TextField()
    policy_version = models.CharField(max_length=64, default='agom-responsibility.v1')
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    revocation_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='revoked_governed_responsibilities',
    )
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-revoked_at', '-id']
        constraints = [
            models.UniqueConstraint(fields=['organization', 'idempotency_key'], name='uniq_govresp_revoke_idem'),
        ]
        indexes = [models.Index(fields=['organization', '-revoked_at'], name='idx_govresp_revoke_org')]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed responsibility revocations are immutable.')
        if self.assignment_id and self.organization_id:
            assignment_org = (
                GovernedResponsibilityAssignment.objects.filter(pk=self.assignment_id)
                .values_list('organization_id', flat=True)
                .first()
            )
            if assignment_org is not None and str(assignment_org) != str(self.organization_id):
                raise ValidationError('Revocation organization must match the responsibility assignment organization.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed responsibility revocations are immutable and cannot be deleted.')


class GovernedResponsibilityEvent(models.Model):
    """Append-only, organization-scoped hash chain for responsibility governance."""

    class EventType(models.TextChoices):
        GRANTED = 'granted', 'Granted'
        REVOKED = 'revoked', 'Revoked'
        SUPERSEDED = 'superseded', 'Superseded'

    objects = _ImmutableGovernanceQuerySet.as_manager()

    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.PROTECT,
        related_name='governed_responsibility_events',
    )
    assignment = models.ForeignKey(
        GovernedResponsibilityAssignment,
        on_delete=models.PROTECT,
        related_name='governance_events',
    )
    event_type = models.CharField(max_length=24, choices=EventType.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='governed_responsibility_events',
    )
    payload = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        indexes = [models.Index(fields=['organization', 'id'], name='idx_govresp_event_chain')]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed responsibility events are immutable.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed responsibility events are immutable and cannot be deleted.')
