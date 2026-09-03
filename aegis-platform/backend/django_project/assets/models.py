from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
import uuid


class Asset(models.Model):
    class Type(models.TextChoices):
        SOURCE_CODE = 'source_code', _('Source Code')
        WEBSITE = 'website', _('Website (URL)')
        IP_ADDRESS = 'ip_address', _('IP Address')
        DOMAIN = 'domain', _('Domain')
        API_ENDPOINT = 'api_endpoint', _('API Endpoint')
        FILE = 'file', _('File Upload')
        DOCKER_IMAGE = 'docker_image', _('Docker Image')
        NETWORK_RANGE = 'network_range', _('Network Range')
        REPOSITORY = 'repository', _('Code Repository')
        CLOUD_RESOURCE = 'cloud_resource', _('Cloud Resource')
        KUBERNETES = 'kubernetes', _('Kubernetes Cluster')
        MOBILE_APP = 'mobile_app', _('Mobile Application')

    class Environment(models.TextChoices):
        DEVELOPMENT = 'development', _('Development')
        STAGING = 'staging', _('Staging')
        PRODUCTION = 'production', _('Production')

    class Criticality(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='assets')
    name = models.CharField(_('name'), max_length=200)
    slug = models.SlugField(_('slug'), max_length=220)
    type = models.CharField(_('type'), max_length=30, choices=Type.choices)
    description = models.TextField(_('description'), blank=True)
    environment = models.CharField(_('environment'), max_length=20, choices=Environment.choices, default=Environment.DEVELOPMENT)
    criticality = models.CharField(_('criticality'), max_length=20, choices=Criticality.choices, default=Criticality.MEDIUM)

    configuration = models.JSONField(_('configuration'), default=dict, blank=True)
    tags = models.JSONField(_('tags'), default=list, blank=True)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='owned_assets')
    is_active = models.BooleanField(_('active'), default=True)
    last_scanned_at = models.DateTimeField(_('last scanned at'), blank=True, null=True)
    scan_count = models.PositiveIntegerField(_('scan count'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Asset')
        verbose_name_plural = _('Assets')
        ordering = ['-created_at']
        unique_together = ['project', 'slug']
        indexes = [
            models.Index(fields=['project', 'type']),
            models.Index(fields=['project', 'environment']),
            models.Index(fields=['project', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_type_display()})"


class AssetRelationship(models.Model):
    class RelationshipType(models.TextChoices):
        DEPENDS_ON = 'depends_on', _('Depends On')
        CONTAINS = 'contains', _('Contains')
        CONNECTS_TO = 'connects_to', _('Connects To')
        HOSTS = 'hosts', _('Hosts')
        DEPLOYED_ON = 'deployed_on', _('Deployed On')
        SAME_AS = 'same_as', _('Same As')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='asset_relationships')
    source = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='outgoing_relationships')
    target = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='incoming_relationships')
    relationship_type = models.CharField(_('type'), max_length=20, choices=RelationshipType.choices)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Asset Relationship')
        verbose_name_plural = _('Asset Relationships')
        unique_together = ['source', 'target', 'relationship_type']
        indexes = [
            models.Index(fields=['project', 'source']),
            models.Index(fields=['project', 'target']),
        ]


class AssetScanHistory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_history')
    scan = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, related_name='asset_history')
    findings_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    scan_duration = models.FloatField(_('scan duration (seconds)'), default=0)
    status = models.CharField(_('status'), max_length=30)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Asset Scan History')
        verbose_name_plural = _('Asset Scan History')
        ordering = ['-created_at']


class TechnologyFingerprint(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='technologies')
    name = models.CharField(_('name'), max_length=100)
    version = models.CharField(_('version'), max_length=50, blank=True)
    category = models.CharField(_('category'), max_length=50)
    confidence = models.FloatField(_('confidence'), default=0.0)
    source = models.CharField(_('source'), max_length=50)
    evidence = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Technology Fingerprint')
        verbose_name_plural = _('Technology Fingerprints')
        ordering = ['-confidence', 'name']
        indexes = [
            models.Index(fields=['asset', 'category']),
        ]


class AssetAuthorizationQuerySet(models.QuerySet):
    """Prevent bulk ORM operations from bypassing authorization immutability."""

    def update(self, **kwargs):
        raise ValidationError('Asset authorization decisions are immutable; bulk updates are forbidden')

    def delete(self):
        raise ValidationError('Asset authorization decisions are immutable; bulk deletes are forbidden')

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError('Asset authorization decisions are immutable; bulk updates are forbidden')


class AssetAuthorizationManager(models.Manager.from_queryset(AssetAuthorizationQuerySet)):
    pass


class AssetAuthorization(models.Model):
    """Immutable authorization decision used as the security source of truth for network execution."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='authorization_records')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='asset_authorization_actions')
    authorized = models.BooleanField(default=False)
    target_snapshot = models.CharField(max_length=500, blank=True)
    reason = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = AssetAuthorizationManager()

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['asset', '-created_at']),
            models.Index(fields=['asset', 'authorized', '-created_at']),
        ]

    def __str__(self):
        state = 'authorized' if self.authorized else 'revoked'
        return f"{self.asset_id}: {state} by {self.actor_id}"

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Asset authorization decisions are immutable; create a new decision instead')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Asset authorization decisions are immutable and cannot be deleted')
