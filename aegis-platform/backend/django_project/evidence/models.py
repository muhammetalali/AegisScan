import uuid
import hashlib
from django.conf import settings
from django.db import models


class Evidence(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, null=True, blank=True, related_name='evidence')
    asset = models.ForeignKey('assets.Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_records')
    source = models.CharField(max_length=100)
    evidence_type = models.CharField(max_length=50, default='scanner_output')
    raw_output = models.TextField()
    sha256 = models.CharField(max_length=64, editable=False)
    metadata = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)
    collected_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-collected_at']
        indexes = [models.Index(fields=['scan', 'source']), models.Index(fields=['asset', 'collected_at']), models.Index(fields=['finding', 'collected_at'])]

    def save(self, *args, **kwargs):
        self.sha256 = hashlib.sha256(self.raw_output.encode('utf-8', errors='replace')).hexdigest()
        super().save(*args, **kwargs)


class ValidationRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = 'queued', 'Queued'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
        CANCELLED = 'cancelled', 'Cancelled'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='validation_runs')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.SET_NULL, null=True, blank=True, related_name='validation_runs')
    finding_identity_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    authorization_decision = models.ForeignKey('assets.AssetAuthorization', on_delete=models.PROTECT, null=True, blank=True, related_name='validation_runs')
    target_type = models.CharField(max_length=20)
    target_value = models.CharField(max_length=500)
    scope = models.CharField(max_length=500)
    profile = models.CharField(max_length=20, default='full')
    engines = models.JSONField(default=list)
    authorized = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    progress = models.PositiveIntegerField(default=0)
    current_phase = models.CharField(max_length=50, default='queued')
    celery_task_id = models.CharField(max_length=100, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['target_value']),
            models.Index(fields=['finding', 'created_at'], name='evidence_va_finding_8f0f45_idx'),
            models.Index(fields=['authorization_decision'], name='evidence_va_auth_dec_0a6a5a_idx'),
        ]
