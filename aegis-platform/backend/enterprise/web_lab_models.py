from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class WebLabInstance(models.Model):
    """Current lifecycle projection for one sealed lab generation."""

    class Status(models.TextChoices):
        READY = 'ready', 'Ready'
        EXPIRED = 'expired', 'Expired'
        CLEANED = 'cleaned', 'Cleaned'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'enterprise.Organization', on_delete=models.PROTECT, related_name='web_lab_instances')
    project = models.ForeignKey(
        'projects.Project', on_delete=models.PROTECT, related_name='web_lab_instances')
    asset = models.ForeignKey(
        'assets.Asset', on_delete=models.PROTECT, related_name='web_lab_instances')
    definition_id = models.CharField(max_length=80)
    fixture_revision = models.CharField(max_length=64, editable=False)
    variant = models.CharField(max_length=24)
    generation = models.PositiveIntegerField(default=1)
    instance_ref = models.UUIDField(unique=True, editable=False)
    runtime_evidence = models.OneToOneField(
        'evidence.Evidence', on_delete=models.PROTECT, related_name='web_lab_instance')
    image_id = models.CharField(max_length=71, editable=False)
    container_id = models.CharField(max_length=64, editable=False)
    container_name = models.CharField(max_length=96, editable=False)
    target = models.CharField(max_length=500, editable=False)
    provisioned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='provisioned_web_lab_instances')
    supersedes = models.ForeignKey(
        'self', on_delete=models.PROTECT, null=True, blank=True, related_name='reset_successors')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.READY)
    expires_at = models.DateTimeField()
    cleaned_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        ordering = ['-created_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'asset', 'definition_id', 'generation'],
                name='uniq_weblab_generation',
            ),
            models.CheckConstraint(condition=models.Q(generation__gte=1), name='weblab_generation_gte_1'),
            models.CheckConstraint(condition=models.Q(version__gte=1), name='weblab_version_gte_1'),
            models.CheckConstraint(
                condition=(
                    models.Q(status='cleaned', cleaned_at__isnull=False)
                    | (~models.Q(status='cleaned') & models.Q(cleaned_at__isnull=True))
                ),
                name='weblab_cleaned_shape',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'asset', 'status'], name='idx_weblab_project_asset'),
            models.Index(fields=['expires_at', 'status'], name='idx_weblab_expiry_status'),
            models.Index(fields=['definition_id', 'fixture_revision'], name='idx_weblab_definition_rev'),
        ]


class _ImmutableWebLabEventQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Web Lab lifecycle events are immutable and cannot be updated.')

    def delete(self):
        raise ValidationError('Web Lab lifecycle events are immutable and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Web Lab lifecycle events must be created through lifecycle authority.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Web Lab lifecycle events are immutable and cannot be updated.')


class WebLabLifecycleEvent(models.Model):
    """Append-only lifecycle transition proof; the host provisioner is the mutating authority."""

    class EventType(models.TextChoices):
        PROVISIONED = 'provisioned', 'Provisioned'
        EXPIRED = 'expired', 'Expired'
        CLEANED = 'cleaned', 'Cleaned'
        FAILED = 'failed', 'Failed'

    objects = _ImmutableWebLabEventQuerySet.as_manager()

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    instance = models.ForeignKey(
        WebLabInstance, on_delete=models.PROTECT, related_name='lifecycle_events')
    organization = models.ForeignKey(
        'enterprise.Organization', on_delete=models.PROTECT, related_name='web_lab_lifecycle_events')
    project = models.ForeignKey(
        'projects.Project', on_delete=models.PROTECT, related_name='web_lab_lifecycle_events')
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='web_lab_lifecycle_events')
    sequence = models.PositiveIntegerField()
    event_type = models.CharField(max_length=24, choices=EventType.choices)
    idempotency_key = models.CharField(max_length=128, editable=False)
    request_fingerprint = models.CharField(max_length=64, editable=False)
    before_status = models.CharField(max_length=20, blank=True)
    after_status = models.CharField(max_length=20)
    generation = models.PositiveIntegerField()
    runtime_evidence = models.ForeignKey(
        'evidence.Evidence', on_delete=models.PROTECT, null=True, blank=True,
        related_name='web_lab_lifecycle_events')
    details = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True, editable=False)
    entry_hash = models.CharField(max_length=64, unique=True, editable=False)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'enterprise'
        ordering = ['sequence', 'occurred_at', 'id']
        constraints = [
            models.UniqueConstraint(fields=['instance', 'sequence'], name='uniq_weblab_event_sequence'),
            models.UniqueConstraint(fields=['organization', 'idempotency_key'], name='uniq_weblab_org_idem'),
            models.CheckConstraint(condition=models.Q(sequence__gte=1), name='weblab_event_sequence_gte_1'),
            models.CheckConstraint(condition=models.Q(generation__gte=1), name='weblab_event_generation_gte_1'),
        ]
        indexes = [
            models.Index(fields=['project', 'event_type', '-occurred_at'], name='idx_weblab_event_project'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Web Lab lifecycle events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Web Lab lifecycle events are immutable.')
