from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableIASTQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('IAST security records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('IAST security records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('IAST security records must be created through the governed IAST service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('IAST security records are immutable and cannot be updated.')


class IASTSession(models.Model):
    """Immutable tenant, target and authorization binding for one IAST runtime session."""

    objects = _ImmutableIASTQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='iast_sessions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='iast_sessions',
    )
    asset = models.ForeignKey(
        'assets.Asset',
        on_delete=models.PROTECT,
        related_name='iast_sessions',
    )
    scan = models.ForeignKey(
        'scans.Scan',
        on_delete=models.PROTECT,
        related_name='iast_sessions',
    )
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization',
        on_delete=models.PROTECT,
        related_name='iast_sessions',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_iast_sessions',
    )
    provider_identity = models.CharField(max_length=255)
    provider_identity_sha256 = models.CharField(max_length=64, editable=False)
    instrumentation_mode = models.CharField(max_length=32)
    target_snapshot = models.CharField(max_length=500)
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='iast-enterprise.v1')
    contract_snapshot = models.JSONField(default=dict)
    contract_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_iast_session_org_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'asset', '-created_at'], name='idx_iast_session_project_asset'),
            models.Index(fields=['authorization_decision', '-created_at'], name='idx_iast_session_authorization'),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('IAST sessions are immutable.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('IAST sessions are immutable and cannot be deleted.')


class IASTObservation(models.Model):
    """Immutable, evidence-qualified IAST runtime observation."""

    objects = _ImmutableIASTQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        IASTSession,
        on_delete=models.PROTECT,
        related_name='observations',
    )
    finding = models.ForeignKey(
        'vulnerabilities.Vulnerability',
        on_delete=models.PROTECT,
        related_name='iast_observations',
    )
    evidence = models.OneToOneField(
        'evidence.Evidence',
        on_delete=models.PROTECT,
        related_name='iast_observation',
    )
    qualification = models.OneToOneField(
        'enterprise.EvidenceQualificationEvaluation',
        on_delete=models.PROTECT,
        related_name='iast_observation',
    )
    observed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='iast_observations',
    )
    observation_kind = models.CharField(max_length=64)
    rule_id = models.CharField(max_length=200)
    severity = models.CharField(max_length=16)
    confidence = models.CharField(max_length=16)
    source_kind = models.CharField(max_length=100)
    sink_kind = models.CharField(max_length=100)
    location = models.CharField(max_length=500, blank=True)
    trace_id = models.CharField(max_length=128)
    data_labels = models.JSONField(default=list)
    metadata_snapshot = models.JSONField(default=dict)
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    observation_sha256 = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'idempotency_key'],
                name='uniq_iast_observation_session_idem',
            ),
            models.UniqueConstraint(
                fields=['session', 'observation_sha256'],
                name='uniq_iast_observation_session_hash',
            ),
        ]
        indexes = [
            models.Index(fields=['session', 'severity', 'created_at'], name='idx_iast_observation_session'),
            models.Index(fields=['finding', 'created_at'], name='idx_iast_observation_finding'),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('IAST observations are immutable.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('IAST observations are immutable and cannot be deleted.')
