from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


class _ImmutableTemporalQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Governed temporal records are immutable.')

    def delete(self):
        raise ValidationError('Governed temporal records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Governed temporal records must be created through the temporal authority.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Governed temporal records are immutable.')


class GovernedTemporalException(models.Model):
    """Immutable AGOM exception/waiver with explicit temporal and scope lineage."""

    class Kind(models.TextChoices):
        EXCEPTION = 'exception', 'Exception'
        WAIVER = 'waiver', 'Waiver'

    class ScopeKind(models.TextChoices):
        PROJECT = 'project', 'Project'
        ENTITY_TYPE = 'entity_type', 'Entity Type'
        ENTITY = 'entity', 'Entity'
        ACTION = 'action', 'Action'

    objects = _ImmutableTemporalQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_temporal_exceptions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='governed_temporal_exceptions',
    )
    kind = models.CharField(max_length=20, choices=Kind.choices)
    scope_kind = models.CharField(max_length=20, choices=ScopeKind.choices)
    action_id = models.CharField(max_length=128, blank=True)
    entity_type = models.CharField(max_length=80, blank=True)
    entity_id = models.CharField(max_length=128, blank=True)
    effective_from = models.DateTimeField()
    expires_at = models.DateTimeField()
    review_at = models.DateTimeField(null=True, blank=True)
    grace_period_seconds = models.PositiveIntegerField(default=0)
    escalation_level = models.PositiveIntegerField(default=0)
    recurrence = models.JSONField(default=dict, blank=True)
    reason = models.TextField()
    policy_version = models.CharField(max_length=64, default='agom-temporal.v1')
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    grant_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    renewal_of = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='renewals',
    )
    supersedes = models.OneToOneField(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='superseded_by',
    )
    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='issued_governed_temporal_exceptions',
    )
    issued_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-issued_at', '-id']
        indexes = [
            models.Index(fields=['organization', 'project', 'expires_at'], name='idx_govtemp_scope_expiry'),
            models.Index(fields=['project', 'action_id', 'entity_type'], name='idx_govtemp_action_entity'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_govtemp_exception_idem',
            ),
            models.CheckConstraint(
                condition=Q(expires_at__gt=models.F('effective_from')),
                name='govtemp_exception_valid_window',
            ),
            models.CheckConstraint(
                condition=(
                    Q(scope_kind='project', action_id='', entity_type='', entity_id='')
                    | (Q(scope_kind='entity_type', action_id='', entity_id='') & ~Q(entity_type=''))
                    | (Q(scope_kind='entity', action_id='') & ~Q(entity_type='') & ~Q(entity_id=''))
                    | (
                        Q(scope_kind='action')
                        & ~Q(action_id='')
                        & (Q(entity_id='') | ~Q(entity_type=''))
                    )
                ),
                name='govtemp_exception_scope_shape',
            ),
            models.CheckConstraint(
                condition=Q(renewal_of__isnull=True) | Q(supersedes__isnull=True),
                name='govtemp_exception_single_lineage_mode',
            ),
            models.CheckConstraint(
                condition=(
                    Q(review_at__isnull=True)
                    | (
                        Q(review_at__gt=models.F('effective_from'))
                        & Q(review_at__lt=models.F('expires_at'))
                    )
                ),
                name='govtemp_exception_review_window',
            ),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed temporal exceptions are immutable.')
        if self.scope_kind == self.ScopeKind.ACTION and self.entity_id and not self.entity_type:
            raise ValidationError('Action temporal scope cannot bind entity_id without entity_type.')
        parent = self.renewal_of or self.supersedes
        if parent is not None:
            if parent.organization_id != self.organization_id or parent.project_id != self.project_id:
                raise ValidationError('Temporal lineage must remain inside the same tenant/project.')
            current_signature = (
                self.kind,
                self.scope_kind,
                self.action_id,
                self.entity_type,
                self.entity_id,
            )
            parent_signature = (
                parent.kind,
                parent.scope_kind,
                parent.action_id,
                parent.entity_type,
                parent.entity_id,
            )
            if current_signature != parent_signature:
                raise ValidationError('Temporal lineage must preserve kind and exact scope semantics.')
            # Validate persisted lineage state, not reverse-relation caches.
            # Assigning a OneToOne supersedes parent populates parent.superseded_by
            # in memory before this new row is INSERTed, so hasattr() would
            # incorrectly classify the row being created as a prior supersession.
            if GovernedTemporalExceptionRevocation.objects.filter(exception_id=parent.pk).exists():
                raise ValidationError('Revoked temporal exceptions cannot be renewed or superseded.')
            if type(self).objects.filter(supersedes_id=parent.pk).exclude(pk=self.pk).exists():
                raise ValidationError('Already-superseded temporal exceptions cannot be renewed or superseded.')

            renewal_child_ids = list(
                type(self).objects.filter(renewal_of_id=parent.pk)
                .exclude(pk=self.pk)
                .values_list('id', flat=True)
            )
            if renewal_child_ids:
                revoked_child_ids = set(
                    GovernedTemporalExceptionRevocation.objects.filter(
                        exception_id__in=renewal_child_ids,
                    ).values_list('exception_id', flat=True)
                )
                superseded_child_ids = set(
                    type(self).objects.filter(
                        supersedes_id__in=renewal_child_ids,
                    ).values_list('supersedes_id', flat=True)
                )
                active_renewal_exists = any(
                    child_id not in revoked_child_ids and child_id not in superseded_child_ids
                    for child_id in renewal_child_ids
                )
                if active_renewal_exists:
                    if self.renewal_of_id == parent.pk:
                        raise ValidationError('Temporal exception already has a current renewal.')
                    raise ValidationError(
                        'Temporal exception has a current renewal; supersede the current renewal leaf instead.'
                    )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed temporal exceptions are immutable and cannot be deleted.')


class GovernedTemporalExceptionRevocation(models.Model):
    """Immutable revocation; exception/waiver rows are never edited."""

    objects = _ImmutableTemporalQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_temporal_exception_revocations',
    )
    exception = models.OneToOneField(
        GovernedTemporalException,
        on_delete=models.PROTECT,
        related_name='revocation',
    )
    reason = models.TextField()
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    revocation_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    revoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='revoked_governed_temporal_exceptions',
    )
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-revoked_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_govtemp_revoke_idem',
            ),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed temporal exception revocations are immutable.')
        if self.exception_id and self.organization_id:
            exception_org = (
                GovernedTemporalException.objects.filter(pk=self.exception_id)
                .values_list('organization_id', flat=True)
                .first()
            )
            if exception_org is not None and str(exception_org) != str(self.organization_id):
                raise ValidationError('Temporal exception revocation organization mismatch.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed temporal exception revocations are immutable and cannot be deleted.')


class GovernedTemporalEvaluation(models.Model):
    """Immutable server-authoritative temporal decision for a governed operation."""

    class Decision(models.TextChoices):
        ACTIVE = 'active', 'Active'
        NOT_YET_EFFECTIVE = 'not_yet_effective', 'Not Yet Effective'
        EXPIRED = 'expired', 'Expired'
        GRACE_ACTIVE = 'grace_active', 'Grace Active'
        REVIEW_DUE = 'review_due', 'Review Due'
        EXCEPTION_ACTIVE = 'exception_active', 'Exception Active'
        WAIVER_ACTIVE = 'waiver_active', 'Waiver Active'
        HARD_BLOCKED = 'hard_blocked', 'Hard Blocked'

    objects = _ImmutableTemporalQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_temporal_evaluations',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='governed_temporal_evaluations',
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='governed_temporal_evaluations',
    )
    action_id = models.CharField(max_length=128)
    entity_type = models.CharField(max_length=80)
    entity_id = models.CharField(max_length=128)
    effective_from = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    review_at = models.DateTimeField(null=True, blank=True)
    grace_period_seconds = models.PositiveIntegerField(default=0)
    renewal_ref = models.CharField(max_length=128, blank=True)
    recurrence = models.JSONField(default=dict, blank=True)
    escalation_level = models.PositiveIntegerField(default=0)
    exception = models.ForeignKey(
        GovernedTemporalException,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='evaluations',
    )
    decision = models.CharField(max_length=32, choices=Decision.choices)
    allowed = models.BooleanField(default=False)
    reason_codes = models.JSONField(default=list)
    reasons = models.JSONField(default=list)
    hard_blocks = models.JSONField(default=list)
    policy_version = models.CharField(max_length=64)
    policy_snapshot = models.JSONField(default=dict)
    evaluation_context = models.JSONField(default=dict)
    evaluation_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    evaluated_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-evaluated_at', '-id']
        indexes = [
            models.Index(fields=['organization', 'decision', '-evaluated_at'], name='idx_govtemp_eval_org_dec'),
            models.Index(fields=['project', 'action_id', '-evaluated_at'], name='idx_govtemp_eval_action'),
            models.Index(fields=['entity_type', 'entity_id', '-evaluated_at'], name='idx_govtemp_eval_entity'),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        decision__in=['active', 'grace_active', 'exception_active', 'waiver_active'],
                        allowed=True,
                    )
                    | models.Q(
                        decision__in=['not_yet_effective', 'expired', 'review_due', 'hard_blocked'],
                        allowed=False,
                    )
                ),
                name='govtemp_eval_decision_allowed',
            ),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed temporal evaluations are immutable.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed temporal evaluations are immutable and cannot be deleted.')
