from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class CanonicalFinding(models.Model):
    """Project-scoped logical finding shared by observations across scans/engines."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='canonical_findings')
    fingerprint = models.CharField(_('canonical fingerprint'), max_length=64)
    rule_key = models.CharField(_('rule key'), max_length=200)
    title = models.CharField(_('canonical title'), max_length=300)
    category = models.CharField(_('category'), max_length=50, blank=True)
    normalized_target = models.CharField(_('normalized target'), max_length=1000, blank=True)
    source_engines = models.JSONField(_('source engines'), default=list, blank=True)
    observation_count = models.PositiveIntegerField(_('observation count'), default=0)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Canonical Finding')
        verbose_name_plural = _('Canonical Findings')
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'fingerprint'],
                name='canonical_project_fp_uniq',
            ),
        ]
        indexes = [
            models.Index(fields=['project', 'rule_key'], name='canonical_project_rule_idx'),
            models.Index(fields=['project', 'category'], name='canonical_project_cat_idx'),
        ]

    def __str__(self):
        return f"{self.title} ({self.fingerprint[:12]})"


class Vulnerability(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = 'critical', _('Critical')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFO = 'info', _('Informational')

    class Status(models.TextChoices):
        OPEN = 'open', _('Open')
        CONFIRMED = 'confirmed', _('Confirmed')
        IN_PROGRESS = 'in_progress', _('In Progress')
        FIXED = 'fixed', _('Fixed')
        FALSE_POSITIVE = 'false_positive', _('False Positive')
        ACCEPTED_RISK = 'accepted_risk', _('Accepted Risk')
        WONT_FIX = 'wont_fix', _("Won't Fix")
        DUPLICATE = 'duplicate', _('Duplicate')

    class Confidence(models.TextChoices):
        CONFIRMED = 'confirmed', _('Confirmed')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        UNVERIFIED = 'unverified', _('Unverified')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, related_name='vulnerabilities')
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='vulnerabilities')
    asset = models.ForeignKey('assets.Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='vulnerabilities')
    canonical_finding = models.ForeignKey(CanonicalFinding, on_delete=models.SET_NULL, null=True, blank=True, related_name='observations')

    # Identification
    title = models.CharField(_('title'), max_length=300)
    description = models.TextField(_('description'))
    severity = models.CharField(_('severity'), max_length=15, choices=Severity.choices)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.OPEN)
    confidence = models.CharField(_('confidence'), max_length=15, choices=Confidence.choices, default=Confidence.UNVERIFIED)

    # Classification
    category = models.CharField(_('category'), max_length=50, blank=True)
    cwe_id = models.CharField(_('CWE ID'), max_length=20, blank=True)
    cve_ids = models.JSONField(_('CVE IDs'), default=list, blank=True)
    owasp_category = models.CharField(_('OWASP Category'), max_length=50, blank=True)
    tags = models.JSONField(_('tags'), default=list, blank=True)

    # Location
    file_path = models.CharField(_('file path'), max_length=500, blank=True)
    line_start = models.PositiveIntegerField(_('line start'), blank=True, null=True)
    line_end = models.PositiveIntegerField(_('line end'), blank=True, null=True)
    function_name = models.CharField(_('function name'), max_length=200, blank=True)
    code_snippet = models.TextField(_('code snippet'), blank=True)

    # Network location
    url = models.URLField(_('URL'), blank=True)
    parameter = models.CharField(_('parameter'), max_length=200, blank=True)
    method = models.CharField(_('HTTP method'), max_length=10, blank=True)

    # Scoring
    cvss_score = models.FloatField(_('CVSS score'), default=0)
    cvss_vector = models.CharField(_('CVSS vector'), max_length=100, blank=True)
    risk_score = models.FloatField(_('risk score'), default=0)
    exploitability = models.FloatField(_('exploitability'), default=0)
    business_impact = models.FloatField(_('business impact'), default=0)

    # Evidence & Verification
    evidence_count = models.PositiveIntegerField(_('evidence count'), default=0)
    verified_evidence_count = models.PositiveIntegerField(_('verified evidence count'), default=0)
    validation_status = models.CharField(_('validation status'), max_length=20, blank=True)
    validated_at = models.DateTimeField(_('validated at'), blank=True, null=True)
    validated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='validated_vulnerabilities')

    # Remediation
    remediation = models.TextField(_('remediation'), blank=True)
    remediation_complexity = models.CharField(_('remediation complexity'), max_length=20, choices=[('trivial', 'Trivial'), ('easy', 'Easy'), ('moderate', 'Moderate'), ('hard', 'Hard'), ('very_hard', 'Very Hard')], blank=True)
    remediation_effort = models.CharField(_('remediation effort'), max_length=50, blank=True)
    fix_available = models.BooleanField(_('fix available'), default=False)
    fix_version = models.CharField(_('fix version'), max_length=50, blank=True)
    references = models.JSONField(_('references'), default=list, blank=True)

    # Assignment & Tracking
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_vulnerabilities')
    assigned_at = models.DateTimeField(_('assigned at'), blank=True, null=True)
    due_date = models.DateTimeField(_('due date'), blank=True, null=True)

    # Relationships
    related_vulnerabilities = models.ManyToManyField('self', symmetrical=False, blank=True, related_name='related_to')
    duplicate_of = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='duplicates')

    # Metadata
    source_engine = models.CharField(_('source engine'), max_length=100, blank=True)
    raw_data = models.JSONField(_('raw data'), default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    fixed_at = models.DateTimeField(blank=True, null=True)
    fixed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='fixed_vulnerabilities')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Vulnerability')
        verbose_name_plural = _('Vulnerabilities')
        ordering = ['-severity', '-risk_score', '-created_at']
        indexes = [
            models.Index(fields=['project', 'severity', 'status']),
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['asset', 'status']),
            models.Index(fields=['assigned_to', 'status']),
            models.Index(fields=['cve_ids']),
            models.Index(fields=['canonical_finding'], name='vulnerability_canonical_idx'),
        ]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"


class VulnerabilityEvidence(models.Model):
    class Type(models.TextChoices):
        STATIC_ANALYSIS = 'static_analysis', _('Static Analysis')
        DYNAMIC_ANALYSIS = 'dynamic_analysis', _('Dynamic Analysis')
        LOG_ANALYSIS = 'log_analysis', _('Log Analysis')
        CONFIG_CHECK = 'config_check', _('Config Check')
        DEPENDENCY_SCAN = 'dependency_scan', _('Dependency Scan')
        EXTERNAL_INTEL = 'external_intel', _('External Intelligence')
        MANUAL_REVIEW = 'manual_review', _('Manual Review')
        VALIDATION_TEST = 'validation_test', _('Validation Test')

    class Quality(models.TextChoices):
        VERIFIED = 'verified', _('Verified')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        UNVERIFIED = 'unverified', _('Unverified')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='evidences')
    type = models.CharField(_('type'), max_length=30, choices=Type.choices)
    quality = models.CharField(_('quality'), max_length=15, choices=Quality.choices, default=Quality.UNVERIFIED)
    source = models.CharField(_('source'), max_length=100)
    description = models.TextField(_('description'))
    location = models.CharField(_('location'), max_length=500, blank=True)
    raw_data = models.TextField(_('raw data'), blank=True)
    confidence = models.FloatField(_('confidence'), default=0.5)
    corroboration_count = models.PositiveIntegerField(_('corroboration count'), default=0)
    tags = models.JSONField(_('tags'), default=list, blank=True)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(_('verified at'), blank=True, null=True)
    verified_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_evidences')

    class Meta:
        verbose_name = _('Vulnerability Evidence')
        verbose_name_plural = _('Vulnerability Evidences')
        ordering = ['-quality', '-confidence']


class VulnerabilityNote(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vulnerability_notes')
    content = models.TextField(_('content'))
    is_private = models.BooleanField(_('private'), default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Vulnerability Note')
        verbose_name_plural = _('Vulnerability Notes')
        ordering = ['-created_at']


class VulnerabilityAttachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='attachments')
    file = models.FileField(_('file'), upload_to='vulnerability_attachments/')
    filename = models.CharField(_('filename'), max_length=255)
    content_type = models.CharField(_('content type'), max_length=100)
    size = models.PositiveIntegerField(_('size'))
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='uploaded_vulnerability_attachments')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Vulnerability Attachment')
        verbose_name_plural = _('Vulnerability Attachments')
        ordering = ['-created_at']


class VulnerabilityStatusHistory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='status_history')
    old_status = models.CharField(_('old status'), max_length=20, choices=Vulnerability.Status.choices)
    new_status = models.CharField(_('new status'), max_length=20, choices=Vulnerability.Status.choices)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='vulnerability_status_changes')
    reason = models.TextField(_('reason'), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Vulnerability Status History')
        verbose_name_plural = _('Vulnerability Status History')
        ordering = ['-created_at']
