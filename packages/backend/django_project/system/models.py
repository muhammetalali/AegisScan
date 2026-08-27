from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class SystemSettings(models.Model):
    class Category(models.TextChoices):
        GENERAL = 'general', _('General')
        SECURITY = 'security', _('Security')
        SCANNING = 'scanning', _('Scanning')
        NOTIFICATIONS = 'notifications', _('Notifications')
        INTEGRATIONS = 'integrations', _('Integrations')
        STORAGE = 'storage', _('Storage')
        PERFORMANCE = 'performance', _('Performance')
        CUSTOM = 'custom', _('Custom')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(_('key'), max_length=100, unique=True)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    category = models.CharField(_('category'), max_length=20, choices=Category.choices)
    value = models.JSONField(_('value'))
    default_value = models.JSONField(_('default value'))
    value_type = models.CharField(_('value type'), max_length=20, choices=[
        ('string', 'String'),
        ('integer', 'Integer'),
        ('float', 'Float'),
        ('boolean', 'Boolean'),
        ('json', 'JSON'),
        ('list', 'List'),
        ('password', 'Password'),
    ])
    is_sensitive = models.BooleanField(_('sensitive'), default=False)
    is_readonly = models.BooleanField(_('readonly'), default=False)
    requires_restart = models.BooleanField(_('requires restart'), default=False)
    validation_rules = models.JSONField(_('validation rules'), default=dict, blank=True)
    order = models.PositiveIntegerField(_('order'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='updated_settings')

    class Meta:
        verbose_name = _('System Setting')
        verbose_name_plural = _('System Settings')
        ordering = ['category', 'order', 'key']

    def __str__(self):
        return f"{self.category}.{self.key}"


class SystemMetric(models.Model):
    class MetricType(models.TextChoices):
        CPU_USAGE = 'cpu_usage', _('CPU Usage %')
        MEMORY_USAGE = 'memory_usage', _('Memory Usage %')
        DISK_USAGE = 'disk_usage', _('Disk Usage %')
        NETWORK_IN = 'network_in', _('Network In (bytes/s)')
        NETWORK_OUT = 'network_out', _('Network Out (bytes/s)')
        DB_CONNECTIONS = 'db_connections', _('DB Connections')
        DB_QUERY_TIME = 'db_query_time', _('DB Query Time (ms)')
        REDIS_MEMORY = 'redis_memory', _('Redis Memory (MB)')
        REDIS_CONNECTIONS = 'redis_connections', _('Redis Connections')
        CELERY_WORKERS = 'celery_workers', _('Celery Workers')
        CELERY_QUEUE_LENGTH = 'celery_queue_length', _('Celery Queue Length')
        CELERY_ACTIVE_TASKS = 'celery_active_tasks', _('Celery Active Tasks')
        FASTAPI_REQUESTS = 'fastapi_requests', _('FastAPI Requests/min')
        FASTAPI_LATENCY = 'fastapi_latency', _('FastAPI Latency (ms)')
        DJANGO_REQUESTS = 'django_requests', _('Django Requests/min')
        DJANGO_LATENCY = 'django_latency', _('Django Latency (ms)')
        ACTIVE_SCANS = 'active_scans', _('Active Scans')
        SCAN_DURATION_AVG = 'scan_duration_avg', _('Avg Scan Duration (s)')
        FINDINGS_PER_MIN = 'findings_per_min', _('Findings per Minute')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    metric_type = models.CharField(_('metric type'), max_length=50, choices=MetricType.choices)
    value = models.FloatField(_('value'))
    unit = models.CharField(_('unit'), max_length=20)
    labels = models.JSONField(_('labels'), default=dict, blank=True)  # e.g., {'host': 'server1', 'service': 'django'}
    timestamp = models.DateTimeField(_('timestamp'))
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('System Metric')
        verbose_name_plural = _('System Metrics')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['metric_type', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]


class ServiceStatus(models.Model):
    class ServiceName(models.TextChoices):
        POSTGRESQL = 'postgresql', _('PostgreSQL')
        REDIS = 'redis', _('Redis')
        CELERY_WORKER = 'celery_worker', _('Celery Worker')
        CELERY_BEAT = 'celery_beat', _('Celery Beat')
        FASTAPI = 'fastapi', _('FastAPI')
        DJANGO = 'django', _('Django')
        NGINX = 'nginx', _('Nginx')
        DOCKER = 'docker', _('Docker')

    class Status(models.TextChoices):
        HEALTHY = 'healthy', _('Healthy')
        DEGRADED = 'degraded', _('Degraded')
        DOWN = 'down', _('Down')
        UNKNOWN = 'unknown', _('Unknown')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.CharField(_('service'), max_length=30, choices=ServiceName.choices)
    status = models.CharField(_('status'), max_length=15, choices=Status.choices, default=Status.UNKNOWN)
    host = models.CharField(_('host'), max_length=100, default='localhost')
    port = models.PositiveIntegerField(_('port'), blank=True, null=True)
    response_time_ms = models.FloatField(_('response time (ms)'), default=0)
    details = models.JSONField(_('details'), default=dict, blank=True)
    last_check = models.DateTimeField(_('last check'), auto_now=True)
    last_status_change = models.DateTimeField(_('last status change'), blank=True, null=True)
    uptime_percentage = models.FloatField(_('uptime %'), default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Service Status')
        verbose_name_plural = _('Service Statuses')
        unique_together = ['service', 'host', 'port']
        ordering = ['service', 'host']


class Backup(models.Model):
    class Type(models.TextChoices):
        FULL = 'full', _('Full Backup')
        INCREMENTAL = 'incremental', _('Incremental Backup')
        DATABASE = 'database', _('Database Only')
        MEDIA = 'media', _('Media Files Only')
        CONFIG = 'config', _('Configuration Only')

    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        RUNNING = 'running', _('Running')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')

    class Storage(models.TextChoices):
        LOCAL = 'local', _('Local Storage')
        S3 = 's3', _('AWS S3')
        AZURE_BLOB = 'azure_blob', _('Azure Blob')
        GCS = 'gcs', _('Google Cloud Storage')
        FTP = 'ftp', _('FTP/SFTP')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    backup_type = models.CharField(_('type'), max_length=20, choices=Type.choices)
    storage = models.CharField(_('storage'), max_length=20, choices=Storage.choices)
    status = models.CharField(_('status'), max_length=15, choices=Status.choices, default=Status.PENDING)
    file_path = models.CharField(_('file path'), max_length=500, blank=True)
    file_size = models.PositiveIntegerField(_('file size (bytes)'), default=0)
    file_hash = models.CharField(_('file hash (SHA256)'), max_length=64, blank=True)
    encryption_enabled = models.BooleanField(_('encrypted'), default=True)
    started_at = models.DateTimeField(_('started at'), blank=True, null=True)
    completed_at = models.DateTimeField(_('completed at'), blank=True, null=True)
    duration = models.FloatField(_('duration (seconds)'), default=0)
    error_message = models.TextField(_('error message'), blank=True)
    initiated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='initiated_backups')
    celery_task_id = models.CharField(_('celery task ID'), max_length=100, blank=True)
    retention_days = models.PositiveIntegerField(_('retention (days)'), default=30)
    expires_at = models.DateTimeField(_('expires at'), blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Backup')
        verbose_name_plural = _('Backups')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
        ]


class MaintenanceWindow(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    start_time = models.DateTimeField(_('start time'))
    end_time = models.DateTimeField(_('end time'))
    is_recurring = models.BooleanField(_('recurring'), default=False)
    recurrence_rule = models.CharField(_('recurrence rule (RRULE)'), max_length=200, blank=True)
    affected_services = models.JSONField(_('affected services'), default=list)
    notify_users = models.BooleanField(_('notify users'), default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_maintenance_windows')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Maintenance Window')
        verbose_name_plural = _('Maintenance Windows')
        ordering = ['start_time']


class FeatureFlag(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField(_('key'), max_length=100, unique=True)
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    is_enabled = models.BooleanField(_('enabled'), default=False)
    rollout_percentage = models.PositiveIntegerField(_('rollout %'), default=0)  # 0-100
    target_users = models.JSONField(_('target users'), default=list, blank=True)  # User IDs or emails
    target_groups = models.JSONField(_('target groups'), default=list, blank=True)  # Group names
    conditions = models.JSONField(_('conditions'), default=dict, blank=True)  # Custom conditions
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='updated_feature_flags')

    class Meta:
        verbose_name = _('Feature Flag')
        verbose_name_plural = _('Feature Flags')
        ordering = ['key']

    def __str__(self):
        return f"{self.key} ({'ON' if self.is_enabled else 'OFF'})"