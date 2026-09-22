from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableCryptoLifecycleQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Cryptographic lifecycle assessments are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Cryptographic lifecycle assessments are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Cryptographic lifecycle assessments must be created through the governed lifecycle service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Cryptographic lifecycle assessments are immutable and cannot be updated.')


class CryptoLifecycleAssessment(models.Model):
    class LifecycleState(models.TextChoices):
        COMPLIANT = 'compliant', 'Compliant'
        ACTION_REQUIRED = 'action_required', 'Action Required'
        CRITICAL = 'critical', 'Critical'

    class PQCReadiness(models.TextChoices):
        READY = 'ready', 'PQC Ready'
        HYBRID = 'hybrid', 'Hybrid Transition'
        TRANSITION_REQUIRED = 'transition_required', 'Transition Required'
        UNKNOWN = 'unknown', 'Unknown'

    objects = _ImmutableCryptoLifecycleQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='crypto_lifecycle_assessments',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='crypto_lifecycle_assessments',
    )
    asset = models.ForeignKey(
        'assets.Asset',
        on_delete=models.PROTECT,
        related_name='crypto_lifecycle_assessments',
    )
    inventory_snapshot = models.ForeignKey(
        'enterprise.CryptographicInventorySnapshot',
        on_delete=models.PROTECT,
        related_name='lifecycle_assessments',
    )
    predecessor = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='successors',
    )
    evaluated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='crypto_lifecycle_assessments',
    )

    assessment_version = models.PositiveIntegerField()
    lifecycle_state = models.CharField(max_length=24, choices=LifecycleState.choices)
    pqc_readiness = models.CharField(max_length=24, choices=PQCReadiness.choices)

    total_records = models.PositiveIntegerField(default=0)
    weak_deprecated_count = models.PositiveIntegerField(default=0)
    expired_count = models.PositiveIntegerField(default=0)
    expiring_30d_count = models.PositiveIntegerField(default=0)
    expiring_90d_count = models.PositiveIntegerField(default=0)
    quantum_vulnerable_count = models.PositiveIntegerField(default=0)
    quantum_resistant_count = models.PositiveIntegerField(default=0)
    hybrid_count = models.PositiveIntegerField(default=0)

    policy_snapshot = models.JSONField(default=dict)
    migration_plan = models.JSONField(default=dict)
    assessment_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='crypto-lifecycle-pqc.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'asset', 'assessment_version'],
                name='uniq_crypto_lifecycle_asset_version',
            ),
        ]
        indexes = [
            models.Index(
                fields=['project', 'asset', '-assessment_version'],
                name='idx_crypto_lifecycle_latest',
            ),
            models.Index(
                fields=['lifecycle_state', 'pqc_readiness'],
                name='idx_crypto_lifecycle_state',
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Cryptographic lifecycle assessments are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Cryptographic lifecycle assessments are immutable and cannot be deleted.')
