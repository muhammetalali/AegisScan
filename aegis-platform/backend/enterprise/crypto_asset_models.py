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
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='cryptographic_inventory_snapshots',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='cryptographic_inventory_snapshots',
    )
    asset = models.ForeignKey(
        'assets.Asset',
        on_delete=models.PROTECT,
        related_name='cryptographic_inventory_snapshots',
    )
    scan = models.ForeignKey(
        'scans.Scan',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='cryptographic_inventory_snapshots',
    )
    predecessor = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='successors',
    )
    collected_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='cryptographic_inventory_snapshots',
    )
    source_kind = models.CharField(max_length=64)
    source_ref = models.CharField(max_length=255, blank=True)
    source_evidence_refs = models.JSONField(default=list)
    idempotency_key = models.CharField(max_length=128, editable=False)
    inventory_version = models.PositiveIntegerField()
    component_count = models.PositiveIntegerField(default=0)
    inventory_sha256 = models.CharField(max_length=64, editable=False, db_index=True)
    drift_summary = models.JSONField(default=dict)
    drift_sha256 = models.CharField(max_length=64, editable=False)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='crypto-asset-plane.v1')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['asset', 'inventory_version'],
                name='uniq_crypto_inventory_asset_version',
            ),
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_crypto_inventory_org_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'asset', '-inventory_version'], name='idx_crypto_inventory_latest'),
            models.Index(fields=['organization', '-created_at'], name='idx_crypto_inventory_org_time'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Cryptographic inventory snapshots are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Cryptographic inventory snapshots are immutable and cannot be deleted.')


class CryptographicAssetRecord(models.Model):
    class AssetType(models.TextChoices):
        ALGORITHM = 'algorithm', 'Algorithm'
        CERTIFICATE = 'certificate', 'Certificate'
        PROTOCOL = 'protocol', 'Protocol'
        RELATED_MATERIAL = 'related-crypto-material', 'Related Cryptographic Material'

    objects = _ImmutableCryptoQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    snapshot = models.ForeignKey(
        CryptographicInventorySnapshot,
        on_delete=models.PROTECT,
        related_name='components',
    )
    component_ref = models.CharField(max_length=160)
    asset_type = models.CharField(max_length=32, choices=AssetType.choices)
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=500, blank=True)
    owner_ref = models.CharField(max_length=255, blank=True)
    algorithm_family = models.CharField(max_length=100, blank=True)
    primitive = models.CharField(max_length=64, blank=True)
    parameter_set = models.CharField(max_length=120, blank=True)
    key_size = models.PositiveIntegerField(null=True, blank=True)
    curve = models.CharField(max_length=120, blank=True)
    protocol_type = models.CharField(max_length=64, blank=True)
    protocol_version = models.CharField(max_length=64, blank=True)
    material_type = models.CharField(max_length=64, blank=True)
    material_state = models.CharField(max_length=64, blank=True)
    protection_mechanism = models.CharField(max_length=120, blank=True)
    fingerprint_sha256 = models.CharField(max_length=64, blank=True)
    certificate_subject = models.CharField(max_length=500, blank=True)
    certificate_issuer = models.CharField(max_length=500, blank=True)
    certificate_serial = models.CharField(max_length=255, blank=True)
    not_valid_before = models.DateTimeField(null=True, blank=True)
    not_valid_after = models.DateTimeField(null=True, blank=True)
    nist_quantum_security_level = models.PositiveSmallIntegerField(null=True, blank=True)
    relationships = models.JSONField(default=list)
    metadata_snapshot = models.JSONField(default=dict)
    component_sha256 = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['component_ref']
        constraints = [
            models.UniqueConstraint(
                fields=['snapshot', 'component_ref'],
                name='uniq_crypto_component_snapshot_ref',
            ),
        ]
        indexes = [
            models.Index(fields=['snapshot', 'asset_type'], name='idx_crypto_component_kind'),
            models.Index(fields=['algorithm_family'], name='idx_crypto_component_algorithm'),
            models.Index(fields=['not_valid_after'], name='idx_crypto_component_expiry'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Cryptographic asset records are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Cryptographic asset records are immutable and cannot be deleted.')


class CBOMArtifact(models.Model):
    objects = _ImmutableCryptoQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    snapshot = models.OneToOneField(
        CryptographicInventorySnapshot,
        on_delete=models.PROTECT,
        related_name='cbom',
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='generated_cbom_artifacts',
    )
    format = models.CharField(max_length=32, default='cyclonedx-json')
    spec_version = models.CharField(max_length=16, default='1.7')
    serial_number = models.CharField(max_length=128, unique=True)
    document = models.JSONField(default=dict)
    document_sha256 = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [models.Index(fields=['snapshot', 'spec_version'], name='idx_cbom_snapshot_spec')]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('CBOM artifacts are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('CBOM artifacts are immutable and cannot be deleted.')
