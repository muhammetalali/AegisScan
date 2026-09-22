from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableAgenticQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Agentic security records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Agentic security records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Agentic security records must be created through the governed agentic service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Agentic security records are immutable and cannot be updated.')


class AgenticSecurityProfile(models.Model):
    """Immutable enterprise security contract for one governed AI agent identity."""

    objects = _ImmutableAgenticQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='agentic_security_profiles',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='agentic_security_profiles',
    )
    provider_governance_decision = models.ForeignKey(
        'enterprise.ProviderApprovalDecision',
        on_delete=models.PROTECT,
        related_name='agentic_security_profiles',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_agentic_security_profiles',
    )

    agent_name = models.CharField(max_length=180)
    agent_version = models.CharField(max_length=120)
    model_name = models.CharField(max_length=180)
    model_version = models.CharField(max_length=120)
    provider_name = models.CharField(max_length=180)
    provider_version = models.CharField(max_length=120)
    capability = models.CharField(max_length=180, default='ai.agent.runtime')

    allowed_tools = models.JSONField(default=dict)
    data_boundaries = models.JSONField(default=dict)
    prompt_policy = models.JSONField(default=dict)

    idempotency_key = models.CharField(max_length=128, editable=False)
    profile_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='agentic-security.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_agentic_profile_org_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'agent_name', '-created_at'], name='idx_agentic_profile_project'),
            models.Index(fields=['provider_governance_decision', '-created_at'], name='idx_agentic_profile_provider'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Agentic security profiles are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Agentic security profiles are immutable and cannot be deleted.')


class AgenticActionDecision(models.Model):
    """Append-only authorization evidence for one proposed AI agent tool action."""

    class Decision(models.TextChoices):
        ALLOWED = 'allowed', 'Allowed'
        DENIED = 'denied', 'Denied'

    objects = _ImmutableAgenticQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='agentic_action_decisions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='agentic_action_decisions',
    )
    profile = models.ForeignKey(
        AgenticSecurityProfile,
        on_delete=models.PROTECT,
        related_name='action_decisions',
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='agentic_action_decisions',
    )

    tool_name = models.CharField(max_length=180)
    operation = models.CharField(max_length=180)
    prompt_sha256 = models.CharField(max_length=64)
    prompt_length = models.PositiveIntegerField()
    arguments_sha256 = models.CharField(max_length=64)
    argument_keys = models.JSONField(default=list)
    data_labels = models.JSONField(default=list)
    risk_signals = models.JSONField(default=list)
    human_approval_ref = models.CharField(max_length=255, blank=True)

    decision = models.CharField(max_length=16, choices=Decision.choices)
    reason_codes = models.JSONField(default=list)
    evidence_snapshot = models.JSONField(default=dict)
    evidence_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    decision_sha256 = models.CharField(max_length=64, editable=False, db_index=True)

    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='agentic-security.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['profile', 'idempotency_key'],
                name='uniq_agentic_action_profile_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'decision', '-created_at'], name='idx_agentic_action_project'),
            models.Index(fields=['profile', '-created_at'], name='idx_agentic_action_profile'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Agentic action decisions are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Agentic action decisions are immutable and cannot be deleted.')
