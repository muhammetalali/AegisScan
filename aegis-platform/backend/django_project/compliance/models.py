from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
import uuid


class ComplianceFramework(models.Model):
    class FrameworkType(models.TextChoices):
        NIST_800_53 = 'nist_800_53', _('NIST 800-53')
        NIST_CSF = 'nist_csf', _('NIST Cybersecurity Framework')
        ISO_27001 = 'iso_27001', _('ISO 27001')
        ISO_27002 = 'iso_27002', _('ISO 27002')
        PCI_DSS = 'pci_dss', _('PCI DSS')
        HIPAA = 'hipaa', _('HIPAA')
        GDPR = 'gdpr', _('GDPR')
        SOC2 = 'soc2', _('SOC 2')
        CIS_CONTROLS = 'cis_controls', _('CIS Controls')
        CIS_BENCHMARKS = 'cis_benchmarks', _('CIS Benchmarks')
        MITRE_ATTACK = 'mitre_attack', _('MITRE ATT&CK')
        CUSTOM = 'custom', _('Custom Framework')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100)
    framework_type = models.CharField(_('type'), max_length=30, choices=FrameworkType.choices)
    version = models.CharField(_('version'), max_length=20, blank=True)
    description = models.TextField(_('description'), blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    is_system = models.BooleanField(_('system'), default=False)
    controls_count = models.PositiveIntegerField(_('controls count'), default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Compliance Framework')
        verbose_name_plural = _('Compliance Frameworks')
        ordering = ['framework_type', 'name']
        unique_together = ['framework_type', 'version']

    def __str__(self):
        return f"{self.name} v{self.version}"


class ComplianceControl(models.Model):
    class Priority(models.TextChoices):
        MANDATORY = 'mandatory', _('Mandatory')
        HIGH = 'high', _('High')
        MEDIUM = 'medium', _('Medium')
        LOW = 'low', _('Low')
        INFORMATIONAL = 'informational', _('Informational')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='controls')
    control_id = models.CharField(_('control ID'), max_length=50)
    title = models.CharField(_('title'), max_length=300)
    description = models.TextField(_('description'))
    priority = models.CharField(_('priority'), max_length=20, choices=Priority.choices, default=Priority.HIGH)
    category = models.CharField(_('category'), max_length=100, blank=True)
    related_controls = models.JSONField(_('related controls'), default=list, blank=True)
    references = models.JSONField(_('references'), default=list, blank=True)
    implementation_guidance = models.TextField(_('implementation guidance'), blank=True)
    testing_procedure = models.TextField(_('testing procedure'), blank=True)
    remediation_deadline_days = models.PositiveIntegerField(_('remediation deadline (days)'), default=30)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Compliance Control')
        verbose_name_plural = _('Compliance Controls')
        unique_together = ['framework', 'control_id']
        ordering = ['framework', 'control_id']
        indexes = [
            models.Index(fields=['framework', 'priority']),
        ]


class ComplianceAssessment(models.Model):
    class Status(models.TextChoices):
        COMPLIANT = 'compliant', _('Compliant')
        NON_COMPLIANT = 'non_compliant', _('Non-Compliant')
        PARTIAL = 'partial', _('Partially Compliant')
        NOT_APPLICABLE = 'not_applicable', _('Not Applicable')
        NOT_ASSESSED = 'not_assessed', _('Not Assessed')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='compliance_assessments')
    scan = models.ForeignKey('scans.Scan', on_delete=models.SET_NULL, null=True, blank=True, related_name='compliance_assessments')
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='assessments')
    control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE, related_name='assessments')
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.NOT_ASSESSED)
    evidence = models.TextField(_('evidence'), blank=True)
    findings = models.ManyToManyField('vulnerabilities.Vulnerability', blank=True, related_name='compliance_assessments')
    remediation_plan = models.TextField(_('remediation plan'), blank=True)
    remediation_deadline = models.DateTimeField(_('remediation deadline'), blank=True, null=True)
    assessed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='compliance_assessments')
    assessed_at = models.DateTimeField(_('assessed at'), blank=True, null=True)
    next_review = models.DateTimeField(_('next review'), blank=True, null=True)
    notes = models.TextField(_('notes'), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Compliance Assessment')
        verbose_name_plural = _('Compliance Assessments')
        unique_together = ['project', 'framework', 'control']
        ordering = ['framework', 'control__control_id']
        indexes = [
            models.Index(fields=['project', 'status']),
            models.Index(fields=['framework', 'status']),
        ]


class ComplianceReport(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='compliance_reports')
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(_('title'), max_length=300)
    overall_status = models.CharField(_('overall status'), max_length=20, choices=ComplianceAssessment.Status.choices)
    total_controls = models.PositiveIntegerField(_('total controls'), default=0)
    compliant_count = models.PositiveIntegerField(_('compliant'), default=0)
    non_compliant_count = models.PositiveIntegerField(_('non-compliant'), default=0)
    partial_count = models.PositiveIntegerField(_('partial'), default=0)
    not_applicable_count = models.PositiveIntegerField(_('not applicable'), default=0)
    compliance_percentage = models.FloatField(_('compliance %'), default=0)
    report_data = models.JSONField(_('report data'), default=dict)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='generated_compliance_reports')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Compliance Report')
        verbose_name_plural = _('Compliance Reports')
        ordering = ['-created_at']


class Policy(models.Model):
    class PolicyType(models.TextChoices):
        SECURITY = 'security', _('Security Policy')
        DATA_PROTECTION = 'data_protection', _('Data Protection')
        ACCESS_CONTROL = 'access_control', _('Access Control')
        INCIDENT_RESPONSE = 'incident_response', _('Incident Response')
        VULNERABILITY_MANAGEMENT = 'vulnerability_management', _('Vulnerability Management')
        CUSTOM = 'custom', _('Custom Policy')

    class Status(models.TextChoices):
        DRAFT = 'draft', _('Draft')
        ACTIVE = 'active', _('Active')
        ARCHIVED = 'archived', _('Archived')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='policies')
    name = models.CharField(_('name'), max_length=200)
    policy_type = models.CharField(_('type'), max_length=30, choices=PolicyType.choices)
    status = models.CharField(_('status'), max_length=15, choices=Status.choices, default=Status.DRAFT)
    version = models.CharField(_('version'), max_length=20, default='1.0')
    description = models.TextField(_('description'))
    content = models.TextField(_('content'))
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='owned_policies')
    approvers = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='approved_policies', blank=True)
    approved_at = models.DateTimeField(_('approved at'), blank=True, null=True)
    effective_date = models.DateTimeField(_('effective date'), blank=True, null=True)
    review_date = models.DateTimeField(_('review date'), blank=True, null=True)
    tags = models.JSONField(_('tags'), default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Policy')
        verbose_name_plural = _('Policies')
        ordering = ['-created_at']