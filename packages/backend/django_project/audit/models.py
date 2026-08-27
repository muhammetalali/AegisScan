from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import hashlib
import json
import uuid


class AuditLog(models.Model):
    class Action(models.TextChoices):
        LOGIN = 'login', _('Login')
        LOGOUT = 'logout', _('Logout')
        LOGIN_FAILED = 'login_failed', _('Login Failed')
        PASSWORD_CHANGE = 'password_change', _('Password Change')
        PASSWORD_RESET = 'password_reset', _('Password Reset')
        TWO_FACTOR_ENABLE = '2fa_enable', _('2FA Enabled')
        TWO_FACTOR_DISABLE = '2fa_disable', _('2FA Disabled')
        USER_CREATE = 'user_create', _('User Created')
        USER_UPDATE = 'user_update', _('User Updated')
        USER_DELETE = 'user_delete', _('User Deleted')
        USER_ROLE_CHANGE = 'user_role_change', _('User Role Changed')
        USER_PERMISSION_CHANGE = 'user_permission_change', _('User Permission Changed')
        PROJECT_CREATE = 'project_create', _('Project Created')
        PROJECT_UPDATE = 'project_update', _('Project Updated')
        PROJECT_DELETE = 'project_delete', _('Project Deleted')
        PROJECT_ARCHIVE = 'project_archive', _('Project Archived')
        PROJECT_CLONE = 'project_clone', _('Project Cloned')
        PROJECT_MEMBER_ADD = 'project_member_add', _('Project Member Added')
        PROJECT_MEMBER_REMOVE = 'project_member_remove', _('Project Member Removed')
        PROJECT_MEMBER_ROLE_CHANGE = 'project_member_role_change', _('Project Member Role Changed')
        ASSET_CREATE = 'asset_create', _('Asset Created')
        ASSET_UPDATE = 'asset_update', _('Asset Updated')
        ASSET_DELETE = 'asset_delete', _('Asset Deleted')
        SCAN_START = 'scan_start', _('Scan Started')
        SCAN_COMPLETE = 'scan_complete', _('Scan Completed')
        SCAN_CANCEL = 'scan_cancel', _('Scan Cancelled')
        SCAN_RESTART = 'scan_restart', _('Scan Restarted')
        SCAN_SCHEDULE = 'scan_schedule', _('Scan Scheduled')
        VULN_CREATE = 'vuln_create', _('Vulnerability Created')
        VULN_UPDATE = 'vuln_update', _('Vulnerability Updated')
        VULN_STATUS_CHANGE = 'vuln_status_change', _('Vulnerability Status Changed')
        VULN_ASSIGN = 'vuln_assign', _('Vulnerability Assigned')
        VULN_NOTE_ADD = 'vuln_note_add', _('Note Added to Vulnerability')
        VULN_FIX_VERIFY = 'vuln_fix_verify', _('Vulnerability Fix Verified')
        REPORT_GENERATE = 'report_generate', _('Report Generated')
        REPORT_DOWNLOAD = 'report_download', _('Report Downloaded')
        REPORT_SHARE = 'report_share', _('Report Shared')
        REPORT_DELETE = 'report_delete', _('Report Deleted')
        COMPLIANCE_ASSESS = 'compliance_assess', _('Compliance Assessed')
        COMPLIANCE_REPORT = 'compliance_report', _('Compliance Report Generated')
        KNOWLEDGE_CREATE = 'knowledge_create', _('Knowledge Article Created')
        KNOWLEDGE_UPDATE = 'knowledge_update', _('Knowledge Article Updated')
        KNOWLEDGE_PUBLISH = 'knowledge_publish', _('Knowledge Article Published')
        SETTINGS_CHANGE = 'settings_change', _('Settings Changed')
        BACKUP_CREATE = 'backup_create', _('Backup Created')
        BACKUP_RESTORE = 'backup_restore', _('Backup Restored')
        API_KEY_CREATE = 'api_key_create', _('API Key Created')
        API_KEY_REVOKE = 'api_key_revoke', _('API Key Revoked')

    class Result(models.TextChoices):
        SUCCESS = 'success', _('Success')
        FAILURE = 'failure', _('Failure')
        PARTIAL = 'partial', _('Partial')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    impersonated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='impersonated_logs')
    action = models.CharField(_('action'), max_length=50, choices=Action.choices)
    result = models.CharField(_('result'), max_length=15, choices=Result.choices, default=Result.SUCCESS)
    resource_type = models.CharField(_('resource type'), max_length=50, blank=True)
    resource_id = models.CharField(_('resource ID'), max_length=100, blank=True)
    resource_repr = models.CharField(_('resource representation'), max_length=200, blank=True)
    changes = models.JSONField(_('changes'), default=dict, blank=True)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('user agent'), blank=True)
    location = models.CharField(_('location'), max_length=100, blank=True)
    session_id = models.CharField(_('session ID'), max_length=100, blank=True)
    request_id = models.UUIDField(_('request ID'), default=uuid.uuid4)
    error_message = models.TextField(_('error message'), blank=True)
    duration_ms = models.PositiveIntegerField(_('duration (ms)'), default=0)
    sequence = models.PositiveBigIntegerField(_('chain sequence'), null=True, unique=True, editable=False)
    previous_hash = models.CharField(_('previous hash'), max_length=64, blank=True, editable=False)
    entry_hash = models.CharField(_('entry hash'), max_length=64, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action', 'created_at']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['request_id']),
            models.Index(fields=['sequence']),
        ]

    @staticmethod
    def canonical_payload(entry: 'AuditLog', previous_hash: str) -> dict:
        return {
            'sequence': entry.sequence,
            'previous_hash': previous_hash,
            'action': entry.action,
            'result': entry.result,
            'resource_type': entry.resource_type,
            'resource_id': entry.resource_id,
            'resource_repr': entry.resource_repr,
            'changes': entry.changes,
            'metadata': entry.metadata,
            'ip_address': entry.ip_address,
            'user_agent': entry.user_agent,
            'location': entry.location,
            'session_id': entry.session_id,
            'request_id': str(entry.request_id),
            'error_message': entry.error_message,
            'duration_ms': entry.duration_ms,
        }

    @classmethod
    def calculate_hash(cls, entry: 'AuditLog', previous_hash: str) -> str:
        payload = json.dumps(cls.canonical_payload(entry, previous_hash), ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    def __str__(self):
        return f"{self.get_action_display()} by {self.user or 'System'} - {self.get_result_display()}"


class SecurityEvent(models.Model):
    class EventType(models.TextChoices):
        BRUTE_FORCE = 'brute_force', _('Brute Force Attack')
        SUSPICIOUS_LOGIN = 'suspicious_login', _('Suspicious Login')
        PRIVILEGE_ESCALATION = 'privilege_escalation', _('Privilege Escalation')
        DATA_EXFILTRATION = 'data_exfiltration', _('Data Exfiltration')
        UNAUTHORIZED_ACCESS = 'unauthorized_access', _('Unauthorized Access')
        CONFIG_CHANGE = 'config_change', _('Configuration Change')
        SCAN_ANOMALY = 'scan_anomaly', _('Scan Anomaly')
        VULN_SPIKE = 'vuln_spike', _('Vulnerability Spike')
    class Severity(models.TextChoices):
        LOW = 'low', _('Low')
        MEDIUM = 'medium', _('Medium')
        HIGH = 'high', _('High')
        CRITICAL = 'critical', _('Critical')
    class Status(models.TextChoices):
        NEW = 'new', _('New')
        INVESTIGATING = 'investigating', _('Investigating')
        RESOLVED = 'resolved', _('Resolved')
        FALSE_POSITIVE = 'false_positive', _('False Positive')
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(max_length=30, choices=EventType.choices)
    severity = models.CharField(max_length=15, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    title = models.CharField(max_length=300)
    description = models.TextField()
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    target_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='security_events')
    target_resource_type = models.CharField(max_length=50, blank=True)
    target_resource_id = models.CharField(max_length=100, blank=True)
    indicators = models.JSONField(default=list)
    raw_data = models.JSONField(default=dict, blank=True)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_security_events')
    resolved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_security_events')
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolution_notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Security Event')
        verbose_name_plural = _('Security Events')
        ordering = ['-created_at']
        indexes = [models.Index(fields=['event_type', 'severity']), models.Index(fields=['status', 'created_at']), models.Index(fields=['target_user'])]


class DataExport(models.Model):
    class Format(models.TextChoices):
        CSV = 'csv', _('CSV')
        JSON = 'json', _('JSON')
        EXCEL = 'excel', _('Excel')
        PDF = 'pdf', _('PDF')
    class Status(models.TextChoices):
        PENDING = 'pending', _('Pending')
        PROCESSING = 'processing', _('Processing')
        COMPLETED = 'completed', _('Completed')
        FAILED = 'failed', _('Failed')
        EXPIRED = 'expired', _('Expired')
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='data_exports')
    name = models.CharField(max_length=200)
    format = models.CharField(max_length=10, choices=Format.choices)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.PENDING)
    resource_type = models.CharField(max_length=50)
    filters = models.JSONField(default=dict, blank=True)
    fields = models.JSONField(default=list, blank=True)
    file = models.FileField(upload_to='exports/', blank=True, null=True)
    file_size = models.PositiveIntegerField(default=0)
    record_count = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField()
    downloaded_at = models.DateTimeField(blank=True, null=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = _('Data Export')
        verbose_name_plural = _('Data Exports')
        ordering = ['-created_at']
