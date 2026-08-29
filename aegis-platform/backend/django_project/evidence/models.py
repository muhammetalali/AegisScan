import uuid
import hashlib
from django.conf import settings
from django.db import models


class Evidence(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, related_name='evidence')
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
        indexes = [
            models.Index(fields=['scan', 'source']),
            models.Index(fields=['asset', 'collected_at']),
            models.Index(fields=['finding', 'collected_at']),
        ]

    def save(self, *args, **kwargs):
        self.sha256 = hashlib.sha256(self.raw_output.encode('utf-8', errors='replace')).hexdigest()
        super().save(*args, **kwargs)
