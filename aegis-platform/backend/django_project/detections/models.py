from __future__ import annotations

import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Detection evidence records are append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Detection evidence records are append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Detection evidence records must be created through the governed detection service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Detection evidence records are append-only and cannot be updated.')


class DetectionRule(models.Model):
    class State(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        VALIDATED = 'validated', 'Validated'
        PUBLISHED = 'published', 'Published'
        RETIRED = 'retired', 'Retired'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='detection_rules')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='detection_rules')
    slug = models.SlugField(max_length=180)
    title = models.CharField(max_length=240)
    description = models.TextField(blank=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.DRAFT)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_detection_rules')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['organization', 'project', 'slug'], name='uniq_detection_rule_scope_slug'),
        ]
        indexes = [
            models.Index(fields=['project', 'state'], name='idx_detection_rule_project_state'),
            models.Index(fields=['organization', 'state'], name='idx_detection_rule_org_state'),
        ]


class DetectionRevision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule = models.ForeignKey(DetectionRule, on_delete=models.PROTECT, related_name='revisions')
    version = models.PositiveIntegerField()
    contract_version = models.CharField(max_length=32, default='aegis-detection.v1')
    spec = models.JSONField()
    content_sha256 = models.CharField(max_length=64)
    compiled = models.JSONField(default=dict)
    attack_techniques = models.JSONField(default=list)
    source_finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='detection_revisions')
    source_evidence = models.ForeignKey('evidence.Evidence', on_delete=models.PROTECT, null=True, blank=True, related_name='detection_revisions')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='detection_revisions')
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ['rule_id', 'version']
        constraints = [
            models.UniqueConstraint(fields=['rule', 'version'], name='uniq_detection_rule_version'),
            models.UniqueConstraint(fields=['rule', 'content_sha256'], name='uniq_detection_rule_content'),
        ]
        indexes = [
            models.Index(fields=['source_finding', '-created_at'], name='idx_detection_revision_finding'),
            models.Index(fields=['content_sha256'], name='idx_detection_revision_sha'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Detection revisions are immutable; create a new revision.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Detection revisions are immutable and cannot be deleted.')


class DetectionValidation(models.Model):
    class Status(models.TextChoices):
        PASSED = 'passed', 'Passed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    revision = models.ForeignKey(DetectionRevision, on_delete=models.PROTECT, related_name='validations')
    telemetry_sha256 = models.CharField(max_length=64)
    telemetry_count = models.PositiveIntegerField()
    matched_count = models.PositiveIntegerField()
    minimum_matches = models.PositiveIntegerField(default=1)
    status = models.CharField(max_length=20, choices=Status.choices)
    result_sha256 = models.CharField(max_length=64)
    result = models.JSONField(default=dict)
    tested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='detection_validations')
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(fields=['revision', 'telemetry_sha256', 'minimum_matches'], name='uniq_detection_validation_input'),
        ]
        indexes = [models.Index(fields=['revision', 'status'], name='idx_detection_validation_state')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Detection validations are immutable and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Detection validations are immutable and cannot be deleted.')


class DetectionPublication(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    revision = models.ForeignKey(DetectionRevision, on_delete=models.PROTECT, related_name='publications')
    integration = models.ForeignKey('enterprise.ExternalIntegration', on_delete=models.PROTECT, related_name='detection_publications')
    package_sha256 = models.CharField(max_length=64)
    provider = models.CharField(max_length=30)
    transport_status = models.PositiveIntegerField(null=True, blank=True)
    response_sha256 = models.CharField(max_length=64)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='detection_publications')
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(fields=['revision', 'integration', 'package_sha256'], name='uniq_detection_publication_package'),
        ]
        indexes = [models.Index(fields=['integration', '-created_at'], name='idx_detection_publication_integration')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Detection publications are immutable and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Detection publications are immutable and cannot be deleted.')


class DetectionEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    rule = models.ForeignKey(DetectionRule, on_delete=models.PROTECT, related_name='events')
    revision = models.ForeignKey(DetectionRevision, on_delete=models.PROTECT, null=True, blank=True, related_name='events')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='detection_events')
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict)
    entry_sha256 = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AppendOnlyQuerySet.as_manager()

    class Meta:
        ordering = ['id']
        indexes = [models.Index(fields=['rule', 'created_at'], name='idx_detection_event_rule_time')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Detection events are immutable and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Detection events are immutable and cannot be deleted.')
