from __future__ import annotations

import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class SOCAppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('SOC evidence is append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('SOC evidence is append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('SOC evidence records must be created through the governed security operations service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('SOC evidence is append-only and cannot be updated.')


class SecuritySignal(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('enterprise.Organization', on_delete=models.PROTECT, related_name='security_signals')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='security_signals')
    validation = models.ForeignKey('enterprise.DetectionValidation', on_delete=models.PROTECT, related_name='security_signals')
    revision = models.ForeignKey('enterprise.DetectionRevision', on_delete=models.PROTECT, related_name='security_signals')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.PROTECT, related_name='security_signals')
    fingerprint = models.CharField(max_length=64, unique=True)
    severity = models.CharField(max_length=20)
    attack_techniques = models.JSONField(default=list)
    payload_sha256 = models.CharField(max_length=64)
    observed_at = models.DateTimeField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_security_signals')
    created_at = models.DateTimeField(auto_now_add=True)

    objects = SOCAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['-observed_at', '-created_at']
        indexes = [
            models.Index(fields=['project', '-observed_at'], name='idx_soc_signal_project_time'),
            models.Index(fields=['finding', '-observed_at'], name='idx_soc_signal_finding_time'),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Security signals are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Security signals are immutable.')


class InvestigationCaseState(models.Model):
    case = models.OneToOneField('enterprise.InvestigationCase', on_delete=models.CASCADE, primary_key=True, related_name='soc_state')
    base_correlation_key = models.CharField(max_length=64)
    generation = models.PositiveIntegerField(default=1)
    version = models.PositiveIntegerField(default=1)
    decision_action = models.ForeignKey('enterprise.DecisionAction', on_delete=models.PROTECT, null=True, blank=True, related_name='investigation_cases')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = 'enterprise'
        constraints = [models.UniqueConstraint(fields=['base_correlation_key', 'generation'], name='uniq_soc_case_generation')]
        indexes = [
            models.Index(fields=['base_correlation_key', '-generation'], name='idx_soc_case_correlation'),
            models.Index(fields=['decision_action'], name='idx_soc_case_decision_action'),
        ]


class InvestigationSignalLink(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey('enterprise.InvestigationCase', on_delete=models.PROTECT, related_name='signal_links')
    signal = models.OneToOneField(SecuritySignal, on_delete=models.PROTECT, related_name='case_link')
    linked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='investigation_signal_links')
    linked_at = models.DateTimeField(auto_now_add=True)

    objects = SOCAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        constraints = [models.UniqueConstraint(fields=['case', 'signal'], name='uniq_soc_case_signal')]
        indexes = [models.Index(fields=['case', '-linked_at'], name='idx_soc_case_signal_time')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Investigation signal links are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Investigation signal links are immutable.')


class InvestigationAuditEvent(models.Model):
    id = models.BigAutoField(primary_key=True)
    case = models.ForeignKey('enterprise.InvestigationCase', on_delete=models.PROTECT, related_name='soc_events')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='investigation_soc_events')
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict)
    previous_hash = models.CharField(max_length=64, blank=True)
    entry_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = SOCAppendOnlyQuerySet.as_manager()

    class Meta:
        app_label = 'enterprise'
        ordering = ['id']
        indexes = [models.Index(fields=['case', 'id'], name='idx_soc_case_event')]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Investigation audit events are immutable.')
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Investigation audit events are immutable.')
