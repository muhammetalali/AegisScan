from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableCryptoQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Cryptographic inventory records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Cryptographic inventory records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Cryptographic inventory records must be created through the governed crypto service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Cryptographic inventory records are immutable and cannot be updated.')


class CryptographicInventorySnapshot(models.Model):
    objects = _ImmutableCryptoQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization', on_delete=models.PROTECT, related_name='crypto_inventory_snapshots'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.PROTECT, related_name='crypto_inventory_snapshots'
    )
    asset = models.ForeignKey(
        'assets.Asset', on_delete=models.PROTECT, related_name='crypto_inventory_snapshots'
    )
    scan = models.ForeignKey(
        'scans.Scan', on_delete=models.PROTECT, null=True, blank=True, related_name='crypto_inventory_snapshots'
    )
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization', on_delete=models.PROTECT, related_name='crypto_inventory_snapshots'
    )
    predecessor = models.ForeignKey(
        'self', on_delete=models.PROTECT, null=True, blank=True, related_name='successors'
    )
    captured_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='crypto_inventory_snapshots'
    )

    snapshot_version = models.PositiveIntegerField()
    source_type = models.CharField(max_length=64)
    inventory_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    cbom = models.JSONField(default=dict)
    cbom_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    risk_summary = models.JSONField(default=dict)
    drift = models.JSONField(default=dict)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='crypto-asset-cbom.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'asset', 'snapshot_version'],
                name='uniq_crypto_snapshot_asset_version',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'asset', '-snapshot_version'], name='idx_crypto_snapshot_latest'),
            models.Index(fields=['organization', '-created_at'], name='idx_crypto_snapshot_org_time'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Cryptographic inventory snapshots are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Cryptographic inventory snapshots are immutable and cannot be deleted.')


class CryptographicAssetRecord(models.Model):
    class Kind(models.TextChoices):
        CERTIFICATE = 'certificate', 'Certificate'
        KEY = 'key', 'Key'
        PROTOCOL = 'protocol', 'Protocol'
        ALGORITHM = 'algorithm', 'Algorithm'
        LIBRARY = 'library', 'Library'

    class SecurityState(models.TextChoices):
        ACCEPTABLE = 'acceptable', 'Acceptable'
        WEAK = 'weak', 'Weak'
        DEPRECATED = 'deprecated', 'Deprecated'
        EXPIRED = 'expired', 'Expired'
        UNKNOWN = 'unknown', 'Unknown'

    class QuantumState(models.TextChoices):
        VULNERABLE = 'vulnerable', 'Quantum Vulnerable'
        RESISTANT = 'resistant', 'Quantum Resistant'
        HYBRID = 'hybrid', 'Hybrid'
        UNKNOWN = 'unknown', 'Unknown'

    objects = _ImmutableCryptoQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    snapshot = models.ForeignKey(
        CryptographicInventorySnapshot, on_delete=models.PROTECT, related_name='records'
    )
    ordinal = models.PositiveIntegerField()
    kind = models.CharField(max_length=24, choices=Kind.choices)
    name = models.CharField(max_length=255)
    algorithm = models.CharField(max_length=128, blank=True)
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=128, blank=True)
    protocol = models.CharField(max_length=64, blank=True)
    version = models.CharField(max_length=64, blank=True)
    issuer = models.CharField(max_length=500, blank=True)
    subject = models.CharField(max_length=500, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    security_state = models.CharField(max_length=20, choices=SecurityState.choices)
    quantum_state = models.CharField(max_length=20, choices=QuantumState.choices)
    fingerprint_sha256 = models.CharField(max_length=64, editable=False)
    metadata = models.JSONField(default=dict)

    class Meta:
        ordering = ['ordinal', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['snapshot', 'fingerprint_sha256'],
                name='uniq_crypto_record_snapshot_fingerprint',
            ),
            models.UniqueConstraint(
                fields=['snapshot', 'ordinal'],
                name='uniq_crypto_record_snapshot_ordinal',
            ),
        ]
        indexes = [
            models.Index(fields=['snapshot', 'kind'], name='idx_crypto_record_kind'),
            models.Index(fields=['security_state'], name='idx_crypto_record_security'),
            models.Index(fields=['quantum_state'], name='idx_crypto_record_quantum'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Cryptographic asset records are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Cryptographic asset records are immutable and cannot be deleted.')
