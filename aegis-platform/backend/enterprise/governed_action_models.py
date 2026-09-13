from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class _ImmutableGovernedActionQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Governed action execution records are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Governed action execution records are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Governed action execution records must be created through the governed action executor.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Governed action execution records are immutable and cannot be updated.')


class GovernedActionExecution(models.Model):
    """Immutable proof envelope for one successfully executed AGOM action.

    The domain mutation, global audit-chain append, and this envelope are committed
    in one database transaction by the governed action executor. Failed or blocked
    attempts do not consume idempotency keys.
    """

    objects = _ImmutableGovernedActionQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization',
        on_delete=models.PROTECT,
        related_name='governed_action_executions',
    )
    project = models.ForeignKey(
        'projects.Project',
        on_delete=models.PROTECT,
        related_name='governed_action_executions',
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='governed_action_executions',
    )
    action_id = models.CharField(max_length=128)
    entity_type = models.CharField(max_length=80)
    entity_id = models.CharField(max_length=128)
    expected_version = models.PositiveIntegerField()
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False, db_index=True)
    contract_version = models.CharField(max_length=32, default='agom.v1')
    contract_policy_version = models.CharField(max_length=64)
    evaluation_policy_version = models.CharField(max_length=64)
    policy_fingerprint = models.CharField(max_length=64, editable=False)
    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False)
    request_payload = models.JSONField(default=dict)
    before_projection = models.JSONField(default=dict)
    gate_snapshot = models.JSONField(default=list)
    result_payload = models.JSONField(default=dict)
    after_projection = models.JSONField(default=dict)
    audit_log = models.OneToOneField(
        'audit.AuditLog',
        on_delete=models.PROTECT,
        related_name='governed_action_execution',
    )
    execution_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['organization', 'idempotency_key'],
                name='uniq_govact_org_idem',
            ),
        ]
        indexes = [
            models.Index(fields=['organization', 'action_id', '-created_at'], name='idx_govact_org_action'),
            models.Index(fields=['project', 'entity_type', 'entity_id'], name='idx_govact_project_entity'),
            models.Index(fields=['correlation_id'], name='idx_govact_correlation'),
        ]

    def save(self, *args, **kwargs):
        if type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Governed action execution records are immutable.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Governed action execution records are immutable and cannot be deleted.')
