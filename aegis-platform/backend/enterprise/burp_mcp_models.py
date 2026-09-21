from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableBurpMCPQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Burp MCP governance records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Burp MCP governance records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Burp MCP governance records must be created through the governed gateway service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Burp MCP governance records are immutable and cannot be updated.')


class BurpMCPSession(models.Model):
    """Immutable tenant, provider, target and authorization binding for one Burp MCP gateway session."""

    objects = _ImmutableBurpMCPQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    asset = models.ForeignKey(
        'assets.Asset',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    scan = models.ForeignKey(
        'scans.Scan',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    provider_approval = models.ForeignKey(
        'enterprise.ProviderApprovalRecord',
        on_delete=models.PROTECT,
        related_name='burp_mcp_sessions',
    )
    provider_governance_decision = models.ForeignKey(
        'enterprise.ProviderApprovalDecision',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='burp_mcp_sessions',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_burp_mcp_sessions',
    )
    credential_ref = models.ForeignKey(
        'system.CredentialSecret',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='burp_mcp_sessions',
    )
    provider_name = models.CharField(max_length=180)
    provider_version = models.CharField(max_length=120)
    provider_identity_sha256 = models.CharField(max_length=64, editable=False)
    endpoint_origin = models.CharField(max_length=500)
    target_snapshot = models.CharField(max_length=500)
    allowed_tools = models.JSONField(default=list)
    max_invocations = models.PositiveSmallIntegerField(default=20)
    rate_limit_per_minute = models.PositiveSmallIntegerField(default=10)
    expires_at = models.DateTimeField()
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    policy_version = models.CharField(max_length=64, default='burp-mcp-gateway.v1')
    contract_snapshot = models.JSONField(default=dict)
    contract_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_burp_mcp_org_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'asset', '-created_at'], name='idx_burp_mcp_project_asset'),
            models.Index(fields=['provider_approval', '-created_at'], name='idx_burp_mcp_approval'),
            models.Index(fields=['expires_at'], name='idx_burp_mcp_expiry'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Burp MCP sessions are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Burp MCP sessions are immutable and cannot be deleted.')


class BurpMCPInvocation(models.Model):
    """Immutable, evidence-qualified provider invocation committed by the governed gateway."""

    objects = _ImmutableBurpMCPQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        BurpMCPSession,
        on_delete=models.PROTECT,
        related_name='invocations',
    )
    evidence = models.OneToOneField(
        'evidence.Evidence',
        on_delete=models.PROTECT,
        related_name='burp_mcp_invocation',
    )
    qualification = models.OneToOneField(
        'enterprise.EvidenceQualificationEvaluation',
        on_delete=models.PROTECT,
        related_name='burp_mcp_invocation',
    )
    invoked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='burp_mcp_invocations',
    )
    operation = models.CharField(max_length=80)
    provider_tool_name = models.CharField(max_length=180)
    invocation_sequence = models.PositiveIntegerField()
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    arguments_sha256 = models.CharField(max_length=64, editable=False)
    provider_result_sha256 = models.CharField(max_length=64, editable=False)
    evidence_sha256 = models.CharField(max_length=64, editable=False)
    provider_request_id = models.CharField(max_length=128, blank=True)
    result_summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at', 'id']
        constraints = [
            models.UniqueConstraint(
                fields=['session', 'idempotency_key'],
                name='uniq_burp_mcp_invocation_idem',
            ),
            models.UniqueConstraint(
                fields=['session', 'invocation_sequence'],
                name='uniq_burp_mcp_invocation_seq',
            ),
        ]
        indexes = [
            models.Index(fields=['session', 'created_at'], name='idx_burp_mcp_session_time'),
            models.Index(fields=['operation', 'created_at'], name='idx_burp_mcp_operation'),
        ]

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Burp MCP invocations are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Burp MCP invocations are immutable and cannot be deleted.')
