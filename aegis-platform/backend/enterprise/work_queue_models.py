from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class GovernedWorkClaim(models.Model):
    class SourceType(models.TextChoices):
        GOVERNED_ACTION_REQUEST = 'governed_action_request', 'Governed Action Request'
        DECISION_ACTION = 'decision_action', 'Decision Action'
        ASSURANCE_OBLIGATION = 'assurance_obligation', 'Assurance Obligation'
        INVESTIGATION_CASE = 'investigation_case', 'Investigation Case'
        DETECTION_DELIVERY = 'detection_delivery', 'Detection Delivery'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_work_claims',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='governed_work_claims',
    )
    source_type = models.CharField(max_length=40, choices=SourceType.choices)
    source_id = models.CharField(max_length=128)
    claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='governed_work_claims',
    )
    claimed_at = models.DateTimeField(null=True, blank=True)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'source_type', 'source_id'],
                name='uniq_gwork_claim_source',
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(claimed_by__isnull=True, claimed_at__isnull=True, lease_expires_at__isnull=True)
                    | models.Q(claimed_by__isnull=False, claimed_at__isnull=False, lease_expires_at__isnull=False)
                ),
                name='gwork_claim_shape',
            ),
            models.CheckConstraint(condition=models.Q(version__gte=1), name='gwork_claim_version_gte_1'),
        ]
        indexes = [
            models.Index(fields=['project', 'source_type'], name='idx_gwork_project_type'),
            models.Index(fields=['claimed_by', 'lease_expires_at'], name='idx_gwork_claim_lease'),
        ]


class _ImmutableGovernedWorkEventQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Governed work claim events are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Governed work claim events are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Governed work claim events must be created through the work queue authority.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Governed work claim events are immutable and cannot be updated.')


class GovernedWorkClaimEvent(models.Model):
    class EventType(models.TextChoices):
        CLAIMED = 'claimed', 'Claimed'
        RECLAIMED = 'reclaimed', 'Reclaimed'
        RENEWED = 'renewed', 'Renewed'
        RELEASED = 'released', 'Released'

    objects = _ImmutableGovernedWorkEventQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    claim = models.ForeignKey(
        GovernedWorkClaim,
        on_delete=models.PROTECT,
        related_name='events',
    )
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_work_claim_events',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='governed_work_claim_events',
    )
    sequence = models.PositiveIntegerField()
    event_type = models.CharField(max_length=24, choices=EventType.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='governed_work_claim_events',
    )
    idempotency_key = models.CharField(max_length=128)
    request_fingerprint = models.CharField(max_length=64)
    expected_version = models.PositiveIntegerField()
    result_version = models.PositiveIntegerField()
    result_claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='governed_work_claim_results',
    )
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    source_snapshot = models.JSONField(default=dict)
    result_snapshot = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, unique=True, editable=False)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'enterprise'
        ordering = ['sequence', 'occurred_at', 'id']
        constraints = [
            models.UniqueConstraint(fields=['claim', 'sequence'], name='uniq_gwork_event_sequence'),
            models.UniqueConstraint(fields=['organization', 'idempotency_key'], name='uniq_gwork_org_idem'),
            models.CheckConstraint(condition=models.Q(sequence__gte=1), name='gwork_event_sequence_gte_1'),
            models.CheckConstraint(condition=models.Q(result_version=models.F('sequence')), name='gwork_event_result_sequence'),
            models.CheckConstraint(
                condition=models.Q(result_version=models.F('expected_version') + 1),
                name='gwork_event_version_step',
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(result_claimed_by__isnull=True, lease_expires_at__isnull=True)
                    | models.Q(result_claimed_by__isnull=False, lease_expires_at__isnull=False)
                ),
                name='gwork_event_claim_shape',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'occurred_at'], name='idx_gwork_event_project'),
            models.Index(fields=['organization', 'event_type'], name='idx_gwork_event_type'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Governed work claim events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed work claim events are immutable.')
