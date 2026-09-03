import uuid

from django.conf import settings
from django.db import models


class DigitalTwin(models.Model):
    class Status(models.TextChoices):
        BUILDING = 'building', 'Building'
        READY = 'ready', 'Ready'
        DRIFTED = 'drifted', 'Drifted'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='digital_twins')
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.BUILDING)
    environment = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='digital_twins')
    built_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        constraints = [models.UniqueConstraint(fields=['project', 'name'], name='dt_project_name_uniq')]


class DigitalTwinNode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    twin = models.ForeignKey(DigitalTwin, on_delete=models.CASCADE, related_name='nodes')
    asset = models.ForeignKey('assets.Asset', on_delete=models.CASCADE, related_name='digital_twin_nodes')
    node_type = models.CharField(max_length=40, default='asset')
    snapshot = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['twin', 'asset'], name='dt_twin_asset_uniq')]
        indexes = [models.Index(fields=['twin', 'asset'], name='dt_node_twin_asset_idx')]


class TwinScenario(models.Model):
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        COMPLETED = 'completed', 'Completed'
        UNSUPPORTED = 'unsupported', 'Unsupported'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    twin = models.ForeignKey(DigitalTwin, on_delete=models.CASCADE, related_name='scenarios')
    name = models.CharField(max_length=200)
    change_type = models.CharField(max_length=50)
    description = models.TextField(blank=True)
    parameters = models.JSONField(default=dict, blank=True)
    affected_nodes = models.JSONField(default=list, blank=True)
    security_impact = models.FloatField(null=True, blank=True)
    performance_impact = models.FloatField(null=True, blank=True)
    risk_reduction = models.FloatField(null=True, blank=True)
    recommendation = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='twin_scenarios')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
