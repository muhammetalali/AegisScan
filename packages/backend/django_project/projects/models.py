from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class Project(models.Model):
    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        ARCHIVED = 'archived', _('Archived')
        ON_HOLD = 'on_hold', _('On Hold')

    class Environment(models.TextChoices):
        DEVELOPMENT = 'development', _('Development')
        STAGING = 'staging', _('Staging')
        PRODUCTION = 'production', _('Production')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    slug = models.SlugField(_('slug'), max_length=220, unique=True)
    description = models.TextField(_('description'), blank=True)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.ACTIVE)
    environment = models.CharField(_('environment'), max_length=20, choices=Environment.choices, default=Environment.DEVELOPMENT)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='owned_projects')
    members = models.ManyToManyField(settings.AUTH_USER_MODEL, through='ProjectMembership', related_name='projects')
    tags = models.JSONField(_('tags'), default=list, blank=True)
    settings = models.JSONField(_('settings'), default=dict, blank=True)
    # Default scan settings
    default_scan_config = models.JSONField(_('default scan config'), default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    archived_at = models.DateTimeField(_('archived at'), blank=True, null=True)

    class Meta:
        verbose_name = _('Project')
        verbose_name_plural = _('Projects')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', 'status']),
            models.Index(fields=['slug']),
        ]

    def __str__(self):
        return self.name

    def get_member_count(self):
        return self.members.count()

    def get_latest_scan(self):
        return self.scans.order_by('-created_at').first()

    def get_vulnerability_counts(self):
        from vulnerabilities.models import Vulnerability
        return Vulnerability.objects.filter(scan__project=self).values('severity').annotate(count=models.Count('id'))


class ProjectMembership(models.Model):
    class Role(models.TextChoices):
        OWNER = 'owner', _('Owner')
        ADMIN = 'admin', _('Admin')
        MEMBER = 'member', _('Member')
        VIEWER = 'viewer', _('Viewer')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='project_memberships')
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.MEMBER)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['project', 'user']
        verbose_name = _('Project Membership')
        verbose_name_plural = _('Project Memberships')


class ProjectInvitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField(_('email'))
    role = models.CharField(max_length=20, choices=ProjectMembership.Role.choices, default=ProjectMembership.Role.MEMBER)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_invitations')
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    expires_at = models.DateTimeField(_('expires at'))
    accepted_at = models.DateTimeField(_('accepted at'), blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Project Invitation')
        verbose_name_plural = _('Project Invitations')
        ordering = ['-created_at']


class ScanTemplate(models.Model):
    class ScanType(models.TextChoices):
        CODE = 'code', _('Code Scan')
        URL = 'url', _('URL Scan')
        IP = 'ip', _('IP Scan')
        API = 'api', _('API Scan')
        FILE = 'file', _('File Scan')
        DOCKER = 'docker', _('Docker Image Scan')
        NETWORK = 'network', _('Network Range Scan')
        FULL_VALIDATION = 'full_validation', _('Full Validation Platform')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='scan_templates')
    scan_type = models.CharField(_('scan type'), max_length=30, choices=ScanType.choices)
    engines = models.JSONField(_('engines'), default=list)  # List of engine names
    depth = models.CharField(_('depth'), max_length=20, choices=[('quick', 'Quick'), ('standard', 'Standard'), ('deep', 'Deep')], default='standard')
    config = models.JSONField(_('configuration'), default=dict)
    is_default = models.BooleanField(_('default'), default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_templates')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Scan Template')
        verbose_name_plural = _('Scan Templates')
        ordering = ['-created_at']


class ScheduledScan(models.Model):
    class Frequency(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        CUSTOM = 'custom', _('Custom Cron')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='scheduled_scans')
    template = models.ForeignKey(ScanTemplate, on_delete=models.CASCADE, related_name='scheduled_scans')
    frequency = models.CharField(_('frequency'), max_length=20, choices=Frequency.choices, default=Frequency.WEEKLY)
    cron_expression = models.CharField(_('cron expression'), max_length=100, blank=True)
    next_run = models.DateTimeField(_('next run'))
    is_active = models.BooleanField(_('active'), default=True)
    last_run = models.DateTimeField(_('last run'), blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_scheduled_scans')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Scheduled Scan')
        verbose_name_plural = _('Scheduled Scans')
        ordering = ['next_run']