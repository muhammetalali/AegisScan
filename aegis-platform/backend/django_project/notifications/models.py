from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class NotificationChannel(models.Model):
    class ChannelType(models.TextChoices):
        EMAIL = 'email', _('Email')
        SLACK = 'slack', _('Slack')
        TEAMS = 'teams', _('Microsoft Teams')
        DISCORD = 'discord', _('Discord')
        WEBHOOK = 'webhook', _('Webhook')
        IN_APP = 'in_app', _('In-App')
        PUSH = 'push', _('Push Notification')
        SMS = 'sms', _('SMS')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100)
    channel_type = models.CharField(_('type'), max_length=20, choices=ChannelType.choices)
    config = models.JSONField(_('configuration'), default=dict)  # API keys, webhooks, etc.
    is_active = models.BooleanField(_('active'), default=True)
    is_default = models.BooleanField(_('default'), default=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, null=True, blank=True, related_name='notification_channels')
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_channels')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Notification Channel')
        verbose_name_plural = _('Notification Channels')
        ordering = ['-is_default', 'name']

    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"


class NotificationTemplate(models.Model):
    class EventType(models.TextChoices):
        # Scan events
        SCAN_STARTED = 'scan_started', _('Scan Started')
        SCAN_COMPLETED = 'scan_completed', _('Scan Completed')
        SCAN_FAILED = 'scan_failed', _('Scan Failed')
        SCAN_CANCELLED = 'scan_cancelled', _('Scan Cancelled')

        # Vulnerability events
        VULN_CRITICAL_FOUND = 'vuln_critical_found', _('Critical Vulnerability Found')
        VULN_HIGH_FOUND = 'vuln_high_found', _('High Vulnerability Found')
        VULN_ASSIGNED = 'vuln_assigned', _('Vulnerability Assigned')
        VULN_STATUS_CHANGED = 'vuln_status_changed', _('Vulnerability Status Changed')
        VULN_FIXED = 'vuln_fixed', _('Vulnerability Fixed')

        # Report events
        REPORT_GENERATED = 'report_generated', _('Report Generated')
        REPORT_FAILED = 'report_failed', _('Report Generation Failed')

        # Compliance events
        COMPLIANCE_VIOLATION = 'compliance_violation', _('Compliance Violation')
        COMPLIANCE_REPORT = 'compliance_report', _('Compliance Report Ready')

        # System events
        SYSTEM_BACKUP_COMPLETED = 'system_backup_completed', _('Backup Completed')
        SYSTEM_BACKUP_FAILED = 'system_backup_failed', _('Backup Failed')
        SYSTEM_MAINTENANCE = 'system_maintenance', _('Maintenance Window')
        SYSTEM_SERVICE_DOWN = 'system_service_down', _('Service Down')

        # User events
        USER_INVITED = 'user_invited', _('User Invited')
        USER_MENTIONED = 'user_mentioned', _('User Mentioned')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(_('event type'), max_length=50, choices=EventType.choices, unique=True)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)

    # Default channels for this event
    default_channels = models.JSONField(_('default channels'), default=list)

    # Templates per channel
    email_subject = models.CharField(_('email subject'), max_length=200, blank=True)
    email_template = models.TextField(_('email template'), blank=True)
    slack_template = models.TextField(_('slack template'), blank=True)
    teams_template = models.TextField(_('teams template'), blank=True)
    in_app_title = models.CharField(_('in-app title'), max_length=200, blank=True)
    in_app_message = models.TextField(_('in-app message'), blank=True)

    # Variables available in templates
    available_variables = models.JSONField(_('available variables'), default=list)

    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Notification Template')
        verbose_name_plural = _('Notification Templates')
        ordering = ['event_type']

    def __str__(self):
        return self.name


class Notification(models.Model):
    class Priority(models.TextChoices):
        LOW = 'low', _('Low')
        NORMAL = 'normal', _('Normal')
        HIGH = 'high', _('High')
        URGENT = 'urgent', _('Urgent')

    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        SENT = 'sent', _('Sent')
        DELIVERED = 'delivered', _('Delivered')
        FAILED = 'failed', _('Failed')
        READ = 'read', _('Read')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, null=True, blank=True, related_name='notifications')
    template = models.ForeignKey(NotificationTemplate, on_delete=models.SET_NULL, null=True, blank=True, related_name='notifications')

    event_type = models.CharField(_('event type'), max_length=50)
    title = models.CharField(_('title'), max_length=300)
    message = models.TextField(_('message'))
    priority = models.CharField(_('priority'), max_length=10, choices=Priority.choices, default=Priority.NORMAL)
    status = models.CharField(_('status'), max_length=15, choices=Status.choices, default=Status.PENDING)

    # Related resources
    resource_type = models.CharField(_('resource type'), max_length=50, blank=True)
    resource_id = models.CharField(_('resource ID'), max_length=100, blank=True)
    action_url = models.CharField(_('action URL'), max_length=500, blank=True)

    # Delivery tracking
    channels = models.JSONField(_('channels'), default=list)
    sent_at = models.DateTimeField(_('sent at'), blank=True, null=True)
    delivered_at = models.DateTimeField(_('delivered at'), blank=True, null=True)
    read_at = models.DateTimeField(_('read at'), blank=True, null=True)
    error_message = models.TextField(_('error message'), blank=True)
    retry_count = models.PositiveIntegerField(_('retry count'), default=0)
    max_retries = models.PositiveIntegerField(_('max retries'), default=3)

    # Metadata
    data = models.JSONField(_('data'), default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Notification')
        verbose_name_plural = _('Notifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['project', 'event_type']),
        ]

    def __str__(self):
        return f"{self.title} - {self.user.email}"


class NotificationPreference(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notification_preferences')
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, null=True, blank=True, related_name='notification_preferences')

    # Global settings
    email_enabled = models.BooleanField(_('email enabled'), default=True)
    in_app_enabled = models.BooleanField(_('in-app enabled'), default=True)
    push_enabled = models.BooleanField(_('push enabled'), default=False)
    digest_enabled = models.BooleanField(_('digest enabled'), default=False)
    digest_frequency = models.CharField(_('digest frequency'), max_length=20, choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
    ], default='daily')
    quiet_hours_start = models.TimeField(_('quiet hours start'), blank=True, null=True)
    quiet_hours_end = models.TimeField(_('quiet hours end'), blank=True, null=True)
    timezone = models.CharField(_('timezone'), max_length=50, default='UTC')

    # Per-event settings (JSON: event_type -> {enabled_channels, priority_threshold})
    event_preferences = models.JSONField(_('event preferences'), default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Notification Preference')
        verbose_name_plural = _('Notification Preferences')
        unique_together = ['user', 'project']


class NotificationDigest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='digests')
    period_start = models.DateTimeField(_('period start'))
    period_end = models.DateTimeField(_('period end'))
    notification_count = models.PositiveIntegerField(_('notification count'), default=0)
    critical_count = models.PositiveIntegerField(_('critical count'), default=0)
    high_count = models.PositiveIntegerField(_('high count'), default=0)
    medium_count = models.PositiveIntegerField(_('medium count'), default=0)
    low_count = models.PositiveIntegerField(_('low count'), default=0)
    content = models.JSONField(_('content'), default=dict)
    sent_at = models.DateTimeField(_('sent at'), blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Notification Digest')
        verbose_name_plural = _('Notification Digests')
        unique_together = ['user', 'period_start']
        ordering = ['-period_start']