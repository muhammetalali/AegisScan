from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class CampaignAppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Campaign assurance evidence is append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Campaign assurance evidence is append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Campaign assurance evidence must be created through the governed campaign service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Campaign assurance evidence is append-only and cannot be updated.')


class AdversaryCampaign(models.Model):
    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        COMPLETED = 'completed', 'Completed'
        ABORTED = 'aborted', 'Aborted'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='adversary_campaigns')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='adversary_campaigns')
    name = models.CharField(max_length=240)
    source_asset = models.ForeignKey('assets.Asset', on_delete=models.PROTECT, related_name='originating_adversary_campaigns')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    scope_sha256 = models.CharField(max_length=64)
    version = models.PositiveIntegerField(default=1)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_adversary_campaigns')
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    completion_sha256 = models.CharField(max_length=64, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        indexes = [
            models.Index(fields=['project', 'status'], name='idx_campaign_proj_state'),
            models.Index(fields=['source_asset', 'status'], name='idx_campaign_source_state'),
        ]


class CampaignObjective(models.Model):
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        REACHED = 'reached', 'Reached'
        BLOCKED = 'blocked', 'Blocked'
        INCONCLUSIVE = 'inconclusive', 'Inconclusive'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    campaign = models.ForeignKey(AdversaryCampaign, on_delete=models.PROTECT, related_name='objectives')
    target_asset = models.ForeignKey('assets.Asset', on_delete=models.PROTECT, related_name='campaign_objectives')
    title = models.CharField(max_length=240)
    objective_type = models.CharField(max_length=80, default='crown_jewel_access')
    success_criteria = models.JSONField(default=dict)
    attack_techniques = models.JSONField(default=list)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    generation = models.PositiveIntegerField(default=1)
    version = models.PositiveIntegerField(default=1)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_campaign_objectives')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        constraints = [models.UniqueConstraint(fields=['campaign', 'target_asset'], name='uniq_campaign_target_objective')]
        indexes = [models.Index(fields=['campaign', 'status'], name='idx_campaign_obj_state')]


class CampaignObjectiveAssessment(models.Model):
    class Outcome(models.TextChoices):
        REACHED = 'reached', 'Reached'
        BLOCKED = 'blocked', 'Blocked'
        INCONCLUSIVE = 'inconclusive', 'Inconclusive'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    objective = models.ForeignKey(CampaignObjective, on_delete=models.PROTECT, related_name='assessments')
    attack_path = models.ForeignKey('enterprise.AttackPath', on_delete=models.PROTECT, related_name='objective_assessments')
    blast_radius_snapshot = models.ForeignKey('enterprise.BlastRadiusSnapshot', on_delete=models.PROTECT, null=True, blank=True, related_name='objective_assessments')
    evidence = models.ForeignKey('evidence.Evidence', on_delete=models.PROTECT, related_name='campaign_objective_assessments')
    validation_run = models.ForeignKey('evidence.ValidationRun', on_delete=models.PROTECT, null=True, blank=True, related_name='campaign_objective_assessments')
    outcome = models.CharField(max_length=20, choices=Outcome.choices)
    reason_code = models.CharField(max_length=80)
    explanation = models.TextField(blank=True)
    path_risk_score = models.FloatField(default=0)
    blast_radius_score = models.FloatField(default=0)
    objective_generation = models.PositiveIntegerField()
    objective_version = models.PositiveIntegerField()
    proof_sha256 = models.CharField(max_length=64)
    replay_fingerprint = models.CharField(max_length=64, unique=True)
    policy_version = models.CharField(max_length=64, default='campaign-objective.v1')
    assessed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='campaign_objective_assessments')
    assessed_at = models.DateTimeField(auto_now_add=True)
    objects = CampaignAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['assessed_at', 'id']
        indexes = [
            models.Index(fields=['objective', '-assessed_at'], name='idx_campaign_obj_assess'),
            models.Index(fields=['outcome', '-assessed_at'], name='idx_campaign_outcome_time'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Campaign objective assessments are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Campaign objective assessments are immutable.')


class CampaignAuditEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    campaign = models.ForeignKey(AdversaryCampaign, on_delete=models.PROTECT, related_name='audit_events')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True, related_name='campaign_audit_events')
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    objects = CampaignAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['id']
        indexes = [models.Index(fields=['campaign', 'id'], name='idx_campaign_audit_event')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Campaign audit events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Campaign audit events are immutable.')
