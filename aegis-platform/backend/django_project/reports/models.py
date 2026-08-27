from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class Report(models.Model):
    class Type(models.TextChoices):
        TECHNICAL = 'technical', _('Technical Report')
        EXECUTIVE = 'executive', _('Executive Summary')
        COMPLIANCE = 'compliance', _('Compliance Report')
        REMEDIATION = 'remediation', _('Remediation Report')
        FULL = 'full', _('Full Validation Report')
        COMPARISON = 'comparison', _('Comparison Report')
        TREND = 'trend', _('Trend Report')

    class Format(models.TextChoices):
        PDF = 'pdf', _('PDF')
        HTML = 'html', _('HTML')
        MARKDOWN = 'markdown', _('Markdown')
        JSON = 'json', _('JSON')
        CSV = 'csv', _('CSV')
        DOCX = 'docx', _('DOCX')

    class Status(models.TextChoices):
        GENERATING = 'generating', _('Generating')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='reports')
    scan = models.ForeignKey('scans.Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='reports')
    title = models.CharField(_('title'), max_length=300)
    description = models.TextField(_('description'), blank=True)
    report_type = models.CharField(_('type'), max_length=20, choices=Type.choices, default=Type.FULL)
    format = models.CharField(_('format'), max_length=15, choices=Format.choices, default=Format.PDF)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.GENERATING)

    # Content
    content = models.TextField(_('content'), blank=True)
    file = models.FileField(_('file'), upload_to='reports/', blank=True, null=True)
    file_size = models.PositiveIntegerField(_('file size'), default=0)
    file_hash = models.CharField(_('file hash'), max_length=64, blank=True)

    # Data snapshot
    data_snapshot = models.JSONField(_('data snapshot'), default=dict, blank=True)

    # Generation info
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='generated_reports')
    generation_duration = models.FloatField(_('generation duration (seconds)'), default=0)
    template_used = models.CharField(_('template used'), max_length=100, blank=True)

    # Sharing
    is_public = models.BooleanField(_('public'), default=False)
    share_token = models.UUIDField(_('share token'), default=uuid.uuid4, editable=False)
    share_expires_at = models.DateTimeField(_('share expires at'), blank=True, null=True)
    download_count = models.PositiveIntegerField(_('download count'), default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Report')
        verbose_name_plural = _('Reports')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['project', 'report_type']),
            models.Index(fields=['scan']),
            models.Index(fields=['share_token']),
        ]

    def __str__(self):
        return f"{self.title} ({self.get_report_type_display()})"


class ReportTemplate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    report_type = models.CharField(_('type'), max_length=20, choices=Report.Type.choices)
    format = models.CharField(_('format'), max_length=15, choices=Report.Format.choices)
    template_content = models.TextField(_('template content'))
    variables = models.JSONField(_('variables'), default=list, blank=True)  # List of variable definitions
    is_default = models.BooleanField(_('default'), default=False)
    is_system = models.BooleanField(_('system'), default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_report_templates')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Report Template')
        verbose_name_plural = _('Report Templates')
        ordering = ['report_type', 'name']


class ReportSchedule(models.Model):
    class Frequency(models.TextChoices):
        DAILY = 'daily', _('Daily')
        WEEKLY = 'weekly', _('Weekly')
        MONTHLY = 'monthly', _('Monthly')
        QUARTERLY = 'quarterly', _('Quarterly')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='report_schedules')
    name = models.CharField(_('name'), max_length=200)
    template = models.ForeignKey(ReportTemplate, on_delete=models.CASCADE, related_name='schedules')
    frequency = models.CharField(_('frequency'), max_length=20, choices=Frequency.choices)
    recipients = models.JSONField(_('recipients'), default=list)  # List of emails/user IDs
    formats = models.JSONField(_('formats'), default=list)
    is_active = models.BooleanField(_('active'), default=True)
    last_generated = models.DateTimeField(_('last generated'), blank=True, null=True)
    next_generation = models.DateTimeField(_('next generation'))
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_report_schedules')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Report Schedule')
        verbose_name_plural = _('Report Schedules')
        ordering = ['next_generation']


class ReportVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='versions')
    version_number = models.PositiveIntegerField(_('version number'))
    content = models.TextField(_('content'))
    file = models.FileField(_('file'), upload_to='report_versions/', blank=True, null=True)
    changes = models.TextField(_('changes'), blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_report_versions')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Report Version')
        verbose_name_plural = _('Report Versions')
        unique_together = ['report', 'version_number']
        ordering = ['-version_number']


class ReportShare(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_reports')
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='received_shares', null=True, blank=True)
    email = models.EmailField(_('email'), blank=True)
    permission = models.CharField(_('permission'), max_length=20, choices=[('view', 'View'), ('download', 'Download'), ('comment', 'Comment')], default='view')
    expires_at = models.DateTimeField(_('expires at'), blank=True, null=True)
    accessed_at = models.DateTimeField(_('accessed at'), blank=True, null=True)
    access_count = models.PositiveIntegerField(_('access count'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Report Share')
        verbose_name_plural = _('Report Shares')
        ordering = ['-created_at']