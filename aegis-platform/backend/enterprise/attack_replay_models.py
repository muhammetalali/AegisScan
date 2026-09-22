from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableAttackReplayQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Attack replay records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Attack replay records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Attack replay records must be created through the governed replay service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Attack replay records are immutable and cannot be updated.')


class AttackReplayScenario(models.Model):
    """Immutable deterministic replay definition pinned to one validated attack chain."""

    objects = _ImmutableAttackReplayQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='attack_replay_scenarios',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='attack_replay_scenarios',
    )
    attack_path_validation = models.ForeignKey(
        'enterprise.AttackPathValidation',
        on_delete=models.PROTECT,
        related_name='replay_scenarios',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_attack_replay_scenarios',
    )

    isolation_contract = models.JSONField(default=dict)
    source_snapshot = models.JSONField(default=dict)
    expected_controls = models.JSONField(default=list)
    idempotency_key = models.CharField(max_length=128, editable=False)
    scenario_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    request_fingerprint = models.CharField(max_length=64, editable=False, unique=True)
    policy_version = models.CharField(max_length=64, default='attack-replay-sandbox.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_attack_replay_org_idem',
            ),
        ]
        indexes = [
            models.Index(
                fields=['project', '-created_at'],
                name='idx_attack_replay_project',
            ),
            models.Index(
                fields=['attack_path_validation', '-created_at'],
                name='idx_attack_replay_validation',
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Attack replay scenarios are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Attack replay scenarios are immutable and cannot be deleted.')


class AttackReplayRun(models.Model):
    """Immutable evidence-backed result of a side-effect-free deterministic replay."""

    class Outcome(models.TextChoices):
        MATCHED = 'matched', 'Matched'
        DIVERGED = 'diverged', 'Diverged'

    objects = _ImmutableAttackReplayQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='attack_replay_runs',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='attack_replay_runs',
    )
    scenario = models.ForeignKey(
        AttackReplayScenario,
        on_delete=models.PROTECT,
        related_name='runs',
    )
    executed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='attack_replay_runs',
    )

    observed_controls = models.JSONField(default=list)
    observation_evidence = models.JSONField(default=list)
    result_snapshot = models.JSONField(default=dict)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    input_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    result_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    comparison_sha256 = models.CharField(max_length=64, editable=False)
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, unique=True)
    policy_version = models.CharField(max_length=64, default='attack-replay-sandbox.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['scenario', 'idempotency_key'],
                name='uniq_attack_replay_run_idem',
            ),
        ]
        indexes = [
            models.Index(
                fields=['project', 'outcome', '-created_at'],
                name='idx_attack_replay_run_project',
            ),
            models.Index(
                fields=['scenario', '-created_at'],
                name='idx_attack_replay_run_scenario',
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Attack replay runs are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Attack replay runs are immutable and cannot be deleted.')
