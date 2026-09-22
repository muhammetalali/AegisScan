from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableFAIRQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('FAIR quantitative risk analyses are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('FAIR quantitative risk analyses are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('FAIR quantitative risk analyses must be created through the governed FAIR service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('FAIR quantitative risk analyses are immutable and cannot be updated.')


class FAIRQuantitativeRiskAnalysis(models.Model):
    objects = _ImmutableFAIRQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization', on_delete=models.PROTECT, related_name='fair_risk_analyses'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.PROTECT, related_name='fair_risk_analyses'
    )
    vulnerability = models.ForeignKey(
        'vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='fair_risk_analyses'
    )
    risk_correlation = models.ForeignKey(
        'enterprise.RiskCorrelationSnapshot', on_delete=models.PROTECT, related_name='fair_risk_analyses'
    )
    predecessor = models.ForeignKey(
        'self', on_delete=models.PROTECT, null=True, blank=True, related_name='successors'
    )
    analyzed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='fair_risk_analyses'
    )

    analysis_version = models.PositiveIntegerField()
    simulation_iterations = models.PositiveIntegerField()
    simulation_seed = models.PositiveBigIntegerField()
    currency = models.CharField(max_length=3, default='USD')

    assumptions = models.JSONField(default=dict)
    assumption_evidence = models.JSONField(default=dict)
    evidence_snapshot = models.JSONField(default=list)
    assumptions_sha256 = models.CharField(max_length=64, editable=False)
    evidence_sha256 = models.CharField(max_length=64, editable=False)

    loss_event_frequency_mean = models.FloatField()
    annual_loss_mean = models.DecimalField(max_digits=24, decimal_places=2)
    annual_loss_p50 = models.DecimalField(max_digits=24, decimal_places=2)
    annual_loss_p95 = models.DecimalField(max_digits=24, decimal_places=2)
    result_summary = models.JSONField(default=dict)
    result_sha256 = models.CharField(max_length=64, editable=False, db_index=True)

    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='fair-quantitative-risk.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'vulnerability', 'analysis_version'],
                name='uniq_fair_risk_finding_version',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'vulnerability', '-analysis_version'], name='idx_fair_risk_latest'),
            models.Index(fields=['risk_correlation', '-created_at'], name='idx_fair_risk_correlation'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('FAIR quantitative risk analyses are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('FAIR quantitative risk analyses are immutable and cannot be deleted.')
