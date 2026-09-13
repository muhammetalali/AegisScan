import uuid
import hashlib
from django.conf import settings
from django.db import models
from django.core.exceptions import ValidationError


class Evidence(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, null=True, blank=True, related_name='evidence')
    asset = models.ForeignKey('assets.Asset', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.SET_NULL, null=True, blank=True, related_name='evidence_records')
    source = models.CharField(max_length=100)
    evidence_type = models.CharField(max_length=50, default='scanner_output')
    raw_output = models.TextField()
    sha256 = models.CharField(max_length=64, editable=False)
    metadata = models.JSONField(default=dict, blank=True)
    collected_at = models.DateTimeField(auto_now_add=True)
    collected_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-collected_at']
        indexes = [models.Index(fields=['scan', 'source']), models.Index(fields=['asset', 'collected_at']), models.Index(fields=['finding', 'collected_at'])]

    def save(self, *args, **kwargs):
        self.sha256 = hashlib.sha256(self.raw_output.encode('utf-8', errors='replace')).hexdigest()
        super().save(*args, **kwargs)


class ValidationRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = 'queued', 'Queued'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'
        CANCELLED = 'cancelled', 'Cancelled'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='validation_runs')
    finding = models.ForeignKey('vulnerabilities.Vulnerability', on_delete=models.SET_NULL, null=True, blank=True, related_name='validation_runs')
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization', on_delete=models.PROTECT, null=True, blank=True,
        related_name='bound_validations',
    )
    target_type = models.CharField(max_length=20)
    target_value = models.CharField(max_length=500)
    scope = models.CharField(max_length=500)
    profile = models.CharField(max_length=20, default='full')
    engines = models.JSONField(default=list)
    authorized = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    progress = models.PositiveIntegerField(default=0)
    current_phase = models.CharField(max_length=50, default='queued')
    celery_task_id = models.CharField(max_length=100, blank=True)
    result = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['target_value']),
            models.Index(fields=['finding', 'status']),
            models.Index(fields=['authorization_decision'], name='evidence_v_authori_5f0c72_idx'),
        ]


class ImmutableFindingConfirmationQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Finding confirmation records are append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Finding confirmation records are append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Finding confirmation records must be created through the governed confirmation service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Finding confirmation records are append-only and cannot be updated.')


class FindingConfirmation(models.Model):
    class Verdict(models.TextChoices):
        CONFIRMED = 'confirmed', 'Confirmed'
        FALSE_POSITIVE = 'false_positive', 'False Positive'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(
        'vulnerabilities.Vulnerability', on_delete=models.PROTECT,
        related_name='confirmation_records',
    )
    validation_run = models.OneToOneField(
        ValidationRun, on_delete=models.PROTECT,
        related_name='finding_confirmation',
    )
    evidence = models.ForeignKey(
        Evidence, on_delete=models.PROTECT,
        related_name='finding_confirmations',
    )
    authorization_decision = models.ForeignKey(
        'assets.AssetAuthorization', on_delete=models.PROTECT,
        related_name='finding_confirmations',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name='finding_confirmations',
    )
    verdict = models.CharField(max_length=20, choices=Verdict.choices)
    finding_present = models.BooleanField()
    policy_version = models.CharField(max_length=64, default='finding-confirmation.v1')
    evidence_sha256 = models.CharField(max_length=64)
    result_sha256 = models.CharField(max_length=64)
    request_fingerprint = models.CharField(max_length=64)
    rationale = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ImmutableFindingConfirmationQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(verdict='confirmed', finding_present=True)
                    | models.Q(verdict='false_positive', finding_present=False)
                ),
                name='evidence_confirmation_verdict_presence',
            ),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Finding confirmation records are immutable and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Finding confirmation records are immutable and cannot be deleted.')


class ImmutableFindingDispositionQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Finding disposition records are append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Finding disposition records are append-only and cannot be deleted.')

    def bulk_create(self, objs, **kwargs):
        raise ValidationError('Finding disposition records must be created through the governed disposition service.')

    def bulk_update(self, objs, fields, **kwargs):
        raise ValidationError('Finding disposition records are append-only and cannot be updated.')


class FindingDisposition(models.Model):
    class Disposition(models.TextChoices):
        ACCEPTED_RISK = 'accepted_risk', 'Accepted Risk'
        WONT_FIX = 'wont_fix', "Won't Fix"
        DUPLICATE = 'duplicate', 'Duplicate'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(
        'vulnerabilities.Vulnerability', on_delete=models.PROTECT,
        related_name='disposition_records',
    )
    disposition = models.CharField(max_length=20, choices=Disposition.choices)
    organization = models.ForeignKey(
        'enterprise.Organization', on_delete=models.PROTECT,
        related_name='finding_dispositions',
    )
    risk_correlation = models.ForeignKey(
        'enterprise.RiskCorrelationSnapshot', on_delete=models.PROTECT,
        null=True, blank=True, related_name='finding_dispositions',
    )
    duplicate_of = models.ForeignKey(
        'vulnerabilities.Vulnerability', on_delete=models.PROTECT,
        null=True, blank=True, related_name='duplicate_disposition_records',
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name='finding_dispositions',
    )
    approving_role = models.CharField(max_length=20)
    policy_version = models.CharField(max_length=64, default='finding-disposition.v1')
    risk_correlation_sha256 = models.CharField(max_length=64, blank=True)
    request_fingerprint = models.CharField(max_length=64, unique=True)
    rationale = models.TextField()
    review_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ImmutableFindingDispositionQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['finding', '-created_at'], name='idx_finddisp_finding_time'),
            models.Index(fields=['organization', 'disposition'], name='idx_finddisp_org_kind'),
            models.Index(fields=['review_at'], name='idx_finddisp_review_at'),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        ('disposition__in', ['accepted_risk', 'wont_fix']),
                        ('risk_correlation__isnull', False),
                        ('duplicate_of__isnull', True),
                        ('review_at__isnull', False),
                    )
                    | models.Q(
                        ('disposition', 'duplicate'),
                        ('risk_correlation__isnull', True),
                        ('duplicate_of__isnull', False),
                        ('review_at__isnull', True),
                    )
                ),
                name='evidence_disposition_lineage_shape',
            ),
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError('Finding disposition records are immutable and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Finding disposition records are immutable and cannot be deleted.')
