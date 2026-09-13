from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class AssuranceObligationEventQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Assurance obligation events are append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Assurance obligation events are append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Assurance obligation events must be created through the governed obligation service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Assurance obligation events are append-only and cannot be updated.')


class AssuranceObligation(models.Model):
    class Kind(models.TextChoices):
        DISPOSITION_REVIEW = 'disposition_review', 'Disposition Review'
        RECURRENCE_REVIEW = 'recurrence_review', 'Recurrence Review'

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        DUE = 'due', 'Due'
        OVERDUE = 'overdue', 'Overdue'
        SATISFIED = 'satisfied', 'Satisfied'
        SUPERSEDED = 'superseded', 'Superseded'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='assurance_obligations')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='assurance_obligations')
    asset = models.ForeignKey('assets.Asset', on_delete=models.PROTECT, related_name='assurance_obligations')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='assurance_obligations')
    disposition = models.OneToOneField('evidence.FindingDisposition', on_delete=models.PROTECT, related_name='assurance_obligation', null=True, blank=True)
    source_disposition = models.ForeignKey('evidence.FindingDisposition', on_delete=models.PROTECT, related_name='recurrence_assurance_obligations', null=True, blank=True)
    source_observation = models.OneToOneField('enterprise.AssuranceObservation', on_delete=models.PROTECT, related_name='recurrence_obligation', null=True, blank=True)
    schedule = models.ForeignKey('enterprise.ContinuousAssuranceSchedule', on_delete=models.PROTECT, related_name='governance_obligations')
    kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.DISPOSITION_REVIEW)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    due_at = models.DateTimeField()
    generation = models.PositiveIntegerField(default=1)
    version = models.PositiveIntegerField(default=1)
    last_execution = models.ForeignKey('enterprise.ContinuousAssuranceExecution', on_delete=models.PROTECT, null=True, blank=True, related_name='governance_obligations')
    last_observation = models.ForeignKey('enterprise.AssuranceObservation', on_delete=models.PROTECT, null=True, blank=True, related_name='governance_obligations')
    satisfied_at = models.DateTimeField(null=True, blank=True)
    superseded_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_assurance_obligations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        indexes = [
            models.Index(fields=['project', 'status', 'due_at'], name='idx_aobl_proj_status_due'),
            models.Index(fields=['finding', 'status'], name='idx_aobl_find_status'),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(status='satisfied', satisfied_at__isnull=False, superseded_at__isnull=True)
                    | models.Q(status='superseded', superseded_at__isnull=False, satisfied_at__isnull=True)
                    | models.Q(status__in=['open', 'due', 'overdue'], satisfied_at__isnull=True, superseded_at__isnull=True)
                ),
                name='assurance_obligation_terminal_shape',
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(kind='disposition_review', disposition__isnull=False, source_observation__isnull=True)
                    | models.Q(kind='recurrence_review', disposition__isnull=True, source_observation__isnull=False)
                ),
                name='assurance_obligation_source_shape',
            ),
        ]


class AssuranceObligationEvent(models.Model):
    class EventType(models.TextChoices):
        CREATED = 'created', 'Created'
        DUE = 'due', 'Due'
        OVERDUE = 'overdue', 'Overdue'
        SATISFIED = 'satisfied', 'Satisfied'
        SUPERSEDED = 'superseded', 'Superseded'
        REVALIDATED_PRESENT = 'revalidated_present', 'Revalidated Present'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    obligation = models.ForeignKey(AssuranceObligation, on_delete=models.PROTECT, related_name='events')
    sequence = models.PositiveIntegerField()
    event_type = models.CharField(max_length=32, choices=EventType.choices)
    disposition = models.ForeignKey('evidence.FindingDisposition', on_delete=models.PROTECT, related_name='assurance_obligation_events', null=True, blank=True)
    schedule = models.ForeignKey('enterprise.ContinuousAssuranceSchedule', on_delete=models.PROTECT, related_name='governance_events')
    execution = models.ForeignKey('enterprise.ContinuousAssuranceExecution', on_delete=models.PROTECT, null=True, blank=True, related_name='governance_events')
    observation = models.ForeignKey('enterprise.AssuranceObservation', on_delete=models.PROTECT, null=True, blank=True, related_name='obligation_events')
    risk_correlation = models.ForeignKey('enterprise.RiskCorrelationSnapshot', on_delete=models.PROTECT, null=True, blank=True, related_name='assurance_obligation_events')
    payload = models.JSONField(default=dict)
    payload_sha256 = models.CharField(max_length=64)
    replay_fingerprint = models.CharField(max_length=64, unique=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='assurance_obligation_events')
    occurred_at = models.DateTimeField(auto_now_add=True)
    objects = AssuranceObligationEventQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['sequence', 'occurred_at', 'id']
        constraints = [
            models.UniqueConstraint(fields=['obligation', 'sequence'], name='uniq_aobl_event_sequence'),
        ]
        indexes = [
            models.Index(fields=['obligation', 'event_type'], name='idx_aobl_event_type'),
            models.Index(fields=['occurred_at'], name='idx_aobl_event_time'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Assurance obligation events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Assurance obligation events are immutable.')