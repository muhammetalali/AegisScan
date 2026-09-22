from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableProviderGovernanceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Provider governance decisions are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Provider governance decisions are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Provider governance decisions must be created through the governed provider service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Provider governance decisions are immutable and cannot be updated.')


class ProviderApprovalDecision(models.Model):
    """Append-only enterprise decision for one provider/capability lineage."""

    class Status(models.TextChoices):
        APPROVED = 'approved', 'Approved'
        EXPERIMENTAL = 'experimental', 'Experimental'
        RESTRICTED = 'restricted', 'Restricted'
        REVOKED = 'revoked', 'Revoked'
        REJECTED = 'rejected', 'Rejected'

    class TrustState(models.TextChoices):
        TRUSTED = 'trusted', 'Trusted'
        CONDITIONAL = 'conditional', 'Conditional'
        UNTRUSTED = 'untrusted', 'Untrusted'

    objects = _ImmutableProviderGovernanceQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='provider_approval_decisions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='enterprise_provider_approval_decisions',
    )
    legacy_approval = models.ForeignKey(
        'enterprise.ProviderApprovalRecord',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='enterprise_decisions',
    )
    predecessor = models.ForeignKey(
        'self',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='successors',
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='enterprise_provider_approval_decisions',
    )

    provider_name = models.CharField(max_length=180)
    provider_version = models.CharField(max_length=120)
    capability = models.CharField(max_length=180)
    provider_identity_sha256 = models.CharField(max_length=64, editable=False, db_index=True)

    status = models.CharField(max_length=20, choices=Status.choices)
    trust_state = models.CharField(max_length=20, choices=TrustState.choices)
    decision_version = models.PositiveIntegerField()

    manifest = models.JSONField(default=dict)
    manifest_sha256 = models.CharField(max_length=64, editable=False)
    capability_manifest = models.JSONField(default=dict)
    capability_manifest_sha256 = models.CharField(max_length=64, editable=False)
    supply_chain_evidence = models.JSONField(default=dict)
    supply_chain_sha256 = models.CharField(max_length=64, editable=False)

    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='provider-approval-enterprise.v1')
    rationale = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'provider_name', 'capability', 'decision_version'],
                name='uniq_provider_decision_lineage_version',
            ),
        ]
        indexes = [
            models.Index(
                fields=['project', 'provider_name', 'capability', '-decision_version'],
                name='idx_provider_decision_latest',
            ),
            models.Index(
                fields=['organization', 'status', 'trust_state'],
                name='idx_provider_decision_trust',
            ),
            models.Index(
                fields=['provider_name', 'provider_version', 'capability'],
                name='idx_provider_decision_identity',
            ),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Provider governance decisions are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Provider governance decisions are immutable and cannot be deleted.')
