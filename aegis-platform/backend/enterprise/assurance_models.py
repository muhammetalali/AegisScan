from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class AssuranceAppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Assurance governance evidence is append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Assurance governance evidence is append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Assurance evidence must be created through the governed assurance service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Assurance governance evidence is append-only and cannot be updated.')


class AssuranceConditionState(models.Model):
    class State(models.TextChoices):
        ACTIVE = 'active', 'Active'
        RESOLVED = 'resolved', 'Resolved'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='assurance_condition_states')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='assurance_condition_states')
    asset = models.ForeignKey('assets.Asset', on_delete=models.PROTECT, related_name='assurance_condition_states')
    finding = models.OneToOneField('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='assurance_condition_state')
    condition_key = models.CharField(max_length=64, unique=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.ACTIVE)
    generation = models.PositiveIntegerField(default=1)
    version = models.PositiveIntegerField(default=1)
    material_sha256 = models.CharField(max_length=64, blank=True)
    last_execution = models.ForeignKey('enterprise.ContinuousAssuranceExecution', on_delete=models.PROTECT, null=True, blank=True, related_name='condition_states')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        constraints = [models.UniqueConstraint(fields=['project', 'finding'], name='uniq_assurance_project_finding_state')]
        indexes = [models.Index(fields=['project', 'state'], name='idx_assure_proj_state'), models.Index(fields=['asset', 'state'], name='idx_assure_asset_state')]


class AssuranceObservation(models.Model):
    class Classification(models.TextChoices):
        NEW = 'new', 'New'
        STABLE = 'stable', 'Stable'
        CHANGED = 'changed', 'Changed'
        RESOLVED = 'resolved', 'Resolved'
        RECURRENT = 'recurrent', 'Recurrent'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='assurance_observations')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='assurance_observations')
    asset = models.ForeignKey('assets.Asset', on_delete=models.PROTECT, related_name='assurance_observations')
    execution = models.ForeignKey('enterprise.ContinuousAssuranceExecution', on_delete=models.PROTECT, related_name='governed_observations')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='assurance_observations')
    classification = models.CharField(max_length=20, choices=Classification.choices)
    generation = models.PositiveIntegerField()
    state_version = models.PositiveIntegerField()
    finding_present = models.BooleanField()
    material_sha256 = models.CharField(max_length=64)
    payload_sha256 = models.CharField(max_length=64)
    replay_fingerprint = models.CharField(max_length=64, unique=True)
    evidence = models.ForeignKey('evidence.Evidence', on_delete=models.PROTECT, null=True, blank=True, related_name='assurance_observations')
    prior_closure = models.ForeignKey('enterprise.InvestigationClosure', on_delete=models.PROTECT, null=True, blank=True, related_name='recurrence_observations')
    prior_disposition = models.ForeignKey('evidence.FindingDisposition', on_delete=models.PROTECT, null=True, blank=True, related_name='recurrence_observations')
    payload = models.JSONField(default=dict)
    observed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='assurance_observations')
    observed_at = models.DateTimeField(auto_now_add=True)
    objects = AssuranceAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['observed_at', 'id']
        constraints = [models.UniqueConstraint(fields=['execution', 'finding'], name='uniq_assurance_exec_finding_obs')]
        indexes = [models.Index(fields=['finding', '-observed_at'], name='idx_assure_find_time'), models.Index(fields=['project', 'classification'], name='idx_assure_proj_class')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Assurance observations are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Assurance observations are immutable.')


class AssuranceObligation(models.Model):
    class SourceType(models.TextChoices):
        RISK_REVIEW = 'risk_review', 'Risk Review'
        RECURRENCE = 'recurrence', 'Recurrence'

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        SATISFIED = 'satisfied', 'Satisfied'
        SUPERSEDED = 'superseded', 'Superseded'

    class SLAStatus(models.TextChoices):
        ON_TRACK = 'on_track', 'On Track'
        AT_RISK = 'at_risk', 'At Risk'
        BREACHED = 'breached', 'Breached'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='assurance_obligations')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='assurance_obligations')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='assurance_obligations')
    source_type = models.CharField(max_length=20, choices=SourceType.choices)
    source_disposition = models.ForeignKey('evidence.FindingDisposition', on_delete=models.PROTECT, null=True, blank=True, related_name='assurance_obligations')
    source_observation = models.OneToOneField(AssuranceObservation, on_delete=models.PROTECT, null=True, blank=True, related_name='assurance_obligation')
    source_sha256 = models.CharField(max_length=64)
    source_fingerprint = models.CharField(max_length=64, unique=True)
    policy_id = models.CharField(max_length=120)
    policy_version = models.PositiveIntegerField(default=1)
    sla_hours = models.PositiveIntegerField()
    due_at = models.DateTimeField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    sla_status = models.CharField(max_length=20, choices=SLAStatus.choices, default=SLAStatus.ON_TRACK)
    escalation_level = models.PositiveIntegerField(default=0)
    generation = models.PositiveIntegerField(default=1)
    version = models.PositiveIntegerField(default=1)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='owned_assurance_obligations')
    satisfied_observation = models.ForeignKey(AssuranceObservation, on_delete=models.PROTECT, null=True, blank=True, related_name='satisfied_obligations')
    satisfied_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name='satisfied_assurance_obligations')
    satisfied_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        indexes = [
            models.Index(fields=['project', 'status', 'due_at'], name='idx_assure_obl_proj_due'),
            models.Index(fields=['finding', 'status'], name='idx_assure_obl_find_state'),
            models.Index(fields=['sla_status', 'due_at'], name='idx_assure_obl_sla_due'),
        ]
        constraints = [
            models.CheckConstraint(condition=(models.Q(source_type='risk_review', source_disposition__isnull=False, source_observation__isnull=True) | models.Q(source_type='recurrence', source_observation__isnull=False)), name='assure_obligation_source_shape'),
            models.CheckConstraint(condition=(models.Q(status='satisfied', satisfied_observation__isnull=False, satisfied_by__isnull=False, satisfied_at__isnull=False) | models.Q(status__in=['open', 'superseded'], satisfied_observation__isnull=True, satisfied_by__isnull=True, satisfied_at__isnull=True)), name='assure_obligation_satisfaction_shape'),
        ]


class AssuranceObligationEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    obligation = models.ForeignKey(AssuranceObligation, on_delete=models.PROTECT, related_name='events')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name='assurance_obligation_events')
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = AssuranceAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['id']
        indexes = [models.Index(fields=['obligation', 'id'], name='idx_assure_obl_event')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Assurance obligation events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Assurance obligation events are immutable.')
