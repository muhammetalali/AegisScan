from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class Scan(models.Model):
    class Type(models.TextChoices):
        CODE = 'code', _('Code Scan')
        URL = 'url', _('URL Scan')
        IP = 'ip', _('IP Scan')
        API = 'api', _('API Scan')
        FILE = 'file', _('File Scan')
        DOCKER = 'docker', _('Docker Image Scan')
        NETWORK = 'network', _('Network Range Scan')
        FULL_VALIDATION = 'full_validation', _('Full Validation Platform')

    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        QUEUED = 'queued', _('Queued')
        RUNNING = 'running', _('Running')
        PAUSED = 'paused', _('Paused')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')
        CANCELLED = 'cancelled', _('Cancelled')
        PARTIAL = 'partial', _('Partial')

    class Depth(models.TextChoices):
        QUICK = 'quick', _('Quick (5 min)')
        STANDARD = 'standard', _('Standard (15 min)')
        DEEP = 'deep', _('Deep (45 min)')
        COMPREHENSIVE = 'comprehensive', _('Comprehensive (2+ hours)')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='scans')
    name = models.CharField(_('name'), max_length=200)
    scan_type = models.CharField(_('scan type'), max_length=30, choices=Type.choices)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.PENDING)
    depth = models.CharField(_('depth'), max_length=20, choices=Depth.choices, default=Depth.STANDARD)
    asset = models.ForeignKey('assets.Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='scans')
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization',
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name='bound_scans',
    )
    engines = models.JSONField(_('engines'), default=list)
    config = models.JSONField(_('configuration'), default=dict, blank=True)
    template = models.ForeignKey('projects.ScanTemplate', on_delete=models.SET_NULL, null=True, blank=True, related_name='scans')
    celery_task_id = models.CharField(_('celery task ID'), max_length=100, blank=True)
    started_at = models.DateTimeField(_('started at'), blank=True, null=True)
    completed_at = models.DateTimeField(_('completed at'), blank=True, null=True)
    duration = models.FloatField(_('duration (seconds)'), default=0)
    progress = models.FloatField(_('progress %'), default=0)
    current_phase = models.CharField(_('current phase'), max_length=50, blank=True)
    current_engine = models.CharField(_('current engine'), max_length=100, blank=True)
    security_score = models.FloatField(_('security score'), default=0)
    risk_level = models.CharField(_('risk level'), max_length=20, blank=True)
    findings_count = models.PositiveIntegerField(_('findings count'), default=0)
    critical_count = models.PositiveIntegerField(_('critical count'), default=0)
    high_count = models.PositiveIntegerField(_('high count'), default=0)
    medium_count = models.PositiveIntegerField(_('medium count'), default=0)
    low_count = models.PositiveIntegerField(_('low count'), default=0)
    info_count = models.PositiveIntegerField(_('info count'), default=0)
    false_positive_count = models.PositiveIntegerField(_('false positive count'), default=0)
    engine_results = models.JSONField(_('engine results'), default=dict, blank=True)
    error_message = models.TextField(_('error message'), blank=True)
    error_traceback = models.TextField(_('error traceback'), blank=True)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='initiated_scans')
    scheduled_scan = models.ForeignKey('projects.ScheduledScan', on_delete=models.SET_NULL, null=True, blank=True, related_name='scan_runs')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Scan')
        verbose_name_plural = _('Scans')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['project', 'status']),
            models.Index(fields=['project', 'scan_type']),
            models.Index(fields=['initiated_by']),
            models.Index(fields=['celery_task_id']),
            models.Index(fields=['authorization_decision']),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_scan_type_display()})"

    @property
    def is_running(self):
        return self.status in [Scan.Status.QUEUED, Scan.Status.RUNNING]

    @property
    def is_finished(self):
        return self.status in [Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.CANCELLED, Scan.Status.PARTIAL]


class ScanEngine(models.Model):
    class EngineCategory(models.TextChoices):
        RECON = 'recon', _('Reconnaissance')
        ANALYSIS = 'analysis', _('Analysis')
        INTELLIGENCE = 'intelligence', _('Threat Intelligence')
        VALIDATION = 'validation', _('Validation')
        CONTROL = 'control', _('Control Validation')
        COVERAGE = 'coverage', _('Coverage Gap')
        ATTACK_PATH = 'attack_path', _('Attack Path')
        EVIDENCE_GRAPH = 'evidence_graph', _('Evidence Graph')
        KNOWLEDGE = 'knowledge', _('Knowledge Management')
        AI_EXPLAIN = 'ai_explain', _('AI Explanation')
        POSTURE = 'posture', _('Security Posture')
        COMPLIANCE = 'compliance', _('Compliance')
        DIGITAL_TWIN = 'digital_twin', _('Digital Twin')
        REPORTING = 'reporting', _('Reporting')

    class EngineStatus(models.TextChoices):
        ACTIVE = 'active', _('Active')
        INACTIVE = 'inactive', _('Inactive')
        DEPRECATED = 'deprecated', _('Deprecated')
        EXPERIMENTAL = 'experimental', _('Experimental')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100, unique=True)
    display_name = models.CharField(_('display name'), max_length=150)
    description = models.TextField(_('description'), blank=True)
    category = models.CharField(_('category'), max_length=20, choices=EngineCategory.choices)
    version = models.CharField(_('version'), max_length=20, default='1.0.0')
    status = models.CharField(_('status'), max_length=20, choices=EngineStatus.choices, default=EngineStatus.ACTIVE)
    is_core = models.BooleanField(_('core engine'), default=False)
    requires_docker = models.BooleanField(_('requires docker'), default=False)
    timeout = models.PositiveIntegerField(_('timeout (seconds)'), default=300)
    config_schema = models.JSONField(_('config schema'), default=dict, blank=True)
    default_config = models.JSONField(_('default config'), default=dict, blank=True)
    dependencies = models.JSONField(_('dependencies'), default=list, blank=True)
    order = models.PositiveIntegerField(_('execution order'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Scan Engine')
        verbose_name_plural = _('Scan Engines')
        ordering = ['category', 'order', 'name']

    def __str__(self):
        return f"{self.display_name} ({self.name})"


class ScanEngineExecution(models.Model):
    class ExecutionStatus(models.TextChoices):
        PENDING = 'pending', _('Pending')
        RUNNING = 'running', _('Running')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')
        SKIPPED = 'skipped', _('Skipped')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='engine_executions')
    engine = models.ForeignKey(ScanEngine, on_delete=models.CASCADE, related_name='executions')
    status = models.CharField(_('status'), max_length=20, choices=ExecutionStatus.choices, default=ExecutionStatus.PENDING)
    progress = models.FloatField(_('progress %'), default=0)
    started_at = models.DateTimeField(_('started at'), blank=True, null=True)
    completed_at = models.DateTimeField(_('completed at'), blank=True, null=True)
    duration = models.FloatField(_('duration (seconds)'), default=0)
    findings_found = models.PositiveIntegerField(_('findings found'), default=0)
    evidences_collected = models.PositiveIntegerField(_('evidences collected'), default=0)
    result_data = models.JSONField(_('result data'), default=dict, blank=True)
    error_message = models.TextField(_('error message'), blank=True)
    logs = models.TextField(_('logs'), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Scan Engine Execution')
        verbose_name_plural = _('Scan Engine Executions')
        ordering = ['scan', 'engine__order']
        unique_together = ['scan', 'engine']


class ScanLog(models.Model):
    class Level(models.TextChoices):
        DEBUG = 'debug', _('Debug')
        INFO = 'info', _('Info')
        WARNING = 'warning', _('Warning')
        ERROR = 'error', _('Error')
        CRITICAL = 'critical', _('Critical')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='logs')
    engine_execution = models.ForeignKey(ScanEngineExecution, on_delete=models.SET_NULL, null=True, blank=True, related_name='scan_logs')
    level = models.CharField(_('level'), max_length=10, choices=Level.choices, default=Level.INFO)
    message = models.TextField(_('message'))
    context = models.JSONField(_('context'), default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Scan Log')
        verbose_name_plural = _('Scan Logs')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan', 'level']),
            models.Index(fields=['scan', 'created_at']),
        ]


class ScanComparison(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='scan_comparisons')
    scan_a = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='comparisons_as_a')
    scan_b = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='comparisons_as_b')
    similarity_score = models.FloatField(_('similarity score'), default=0)
    new_findings = models.JSONField(_('new findings'), default=list)
    fixed_findings = models.JSONField(_('fixed findings'), default=list)
    changed_findings = models.JSONField(_('changed findings'), default=list)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_comparisons')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Scan Comparison')
        verbose_name_plural = _('Scan Comparisons')
        unique_together = ['scan_a', 'scan_b']
        ordering = ['-created_at']
