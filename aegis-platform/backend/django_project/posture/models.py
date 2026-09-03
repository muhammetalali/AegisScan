import uuid

from django.conf import settings
from django.db import models


class PostureSnapshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='posture_snapshots')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='posture_snapshots')

    overall_score = models.FloatField()
    rating = models.CharField(max_length=20)
    vulnerability_health = models.FloatField()
    control_effectiveness = models.FloatField()
    evidence_quality = models.FloatField()
    coverage = models.FloatField()

    total_assets = models.PositiveIntegerField(default=0)
    active_assets = models.PositiveIntegerField(default=0)
    scanned_assets = models.PositiveIntegerField(default=0)
    total_findings = models.PositiveIntegerField(default=0)
    open_findings = models.PositiveIntegerField(default=0)
    critical_findings = models.PositiveIntegerField(default=0)
    high_findings = models.PositiveIntegerField(default=0)
    medium_findings = models.PositiveIntegerField(default=0)
    low_findings = models.PositiveIntegerField(default=0)
    verified_findings = models.PositiveIntegerField(default=0)
    evidence_count = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['project', '-created_at'], name='posture_snap_project_created_idx'),
        ]

    def __str__(self):
        return f'{self.project_id}: {self.rating} ({self.overall_score:.2f})'
