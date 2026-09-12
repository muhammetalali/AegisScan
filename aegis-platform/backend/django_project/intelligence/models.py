from __future__ import annotations

import hashlib
import json
import uuid

from django.conf import settings
from django.db import models


class IntelligenceEnrichment(models.Model):
    """Immutable persisted snapshot of live vulnerability intelligence and provenance."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    cve_id = models.CharField(max_length=32, db_index=True)
    sources = models.JSONField(default=dict)
    source_urls = models.JSONField(default=dict)
    provider_failures = models.JSONField(default=list, blank=True)
    confidence = models.FloatField(default=0.0)
    conflicts = models.JSONField(default=list, blank=True)
    recommendation = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    snapshot_sha256 = models.CharField(max_length=64, editable=False)
    observed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    observed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='intelligence_enrichments')

    class Meta:
        ordering = ['-observed_at', '-created_at']
        indexes = [
            models.Index(fields=['cve_id', '-observed_at'], name='intel_cve_observed_idx'),
            models.Index(fields=['observed_by', '-observed_at'], name='intel_actor_observed_idx'),
        ]

    def save(self, *args, **kwargs):
        snapshot = {
            'cve_id': self.cve_id,
            'sources': self.sources or {},
            'source_urls': self.source_urls or {},
            'provider_failures': self.provider_failures or [],
            'confidence': self.confidence,
            'conflicts': self.conflicts or [],
            'recommendation': self.recommendation,
            'explanation': self.explanation,
            'observed_at': self.observed_at.isoformat() if self.observed_at else None,
        }
        canonical = json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        self.snapshot_sha256 = hashlib.sha256(canonical).hexdigest()
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValueError('Intelligence enrichments are immutable; create a new observation')
        super().save(*args, **kwargs)
