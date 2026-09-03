from __future__ import annotations

import hashlib
import json
import uuid

from django.conf import settings
from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        SECURITY = 'security', 'Security'
        VULNERABILITY = 'vulnerability', 'Vulnerability'
        COMPLIANCE = 'compliance', 'Compliance'
        POSTURE = 'posture', 'Posture'
        EXECUTIVE = 'executive', 'Executive'

    class Format(models.TextChoices):
        JSON = 'json', 'JSON'
        HTML = 'html', 'HTML'

    class Status(models.TextChoices):
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='security_reports')
    scan = models.ForeignKey('scans.Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='security_reports')
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    report_type = models.CharField(max_length=30, choices=ReportType.choices)
    format = models.CharField(max_length=10, choices=Format.choices, default=Format.JSON)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.COMPLETED)
    snapshot = models.JSONField(default=dict)
    file = models.FileField(upload_to='security-reports/', blank=True, null=True)
    snapshot_sha256 = models.CharField(max_length=64, editable=False)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='generated_security_reports')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [models.Index(fields=['project', '-created_at'])]

    def save(self, *args, **kwargs):
        canonical = json.dumps(self.snapshot or {}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        self.snapshot_sha256 = hashlib.sha256(canonical).hexdigest()
        super().save(*args, **kwargs)


class ReportSchedule(models.Model):
    class Frequency(models.TextChoices):
        DAILY = 'daily', 'Daily'
        WEEKLY = 'weekly', 'Weekly'
        MONTHLY = 'monthly', 'Monthly'
        CRON = 'cron', 'Cron'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='report_schedules')
    title = models.CharField(max_length=300)
    report_type = models.CharField(max_length=30, choices=Report.ReportType.choices)
    format = models.CharField(max_length=10, choices=Report.Format.choices, default=Report.Format.JSON)
    frequency = models.CharField(max_length=15, choices=Frequency.choices)
    cron_expression = models.CharField(max_length=100, blank=True)
    recipients = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    next_run = models.DateTimeField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_report_schedules')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['next_run', '-created_at']
        indexes = [models.Index(fields=['project', 'is_active', 'next_run'])]
