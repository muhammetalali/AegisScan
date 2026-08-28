from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class SecurityTestSession(models.Model):
    class Status(models.TextChoices):
        PLANNED = "planned", "Planned"
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        COMPLETING = "completing", "Completing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        EXPIRED = "expired", "Expired"
        REVOKED = "revoked", "Revoked"

    class CleanupStatus(models.TextChoices):
        NOT_STARTED = "not_started", "Not Started"
        RUNNING = "running", "Running"
        VERIFIED = "verified", "Verified"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        "projects.Project", on_delete=models.CASCADE, related_name="security_test_sessions"
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="initiated_security_test_sessions",
    )
    name = models.CharField(max_length=200)
    assessment_type = models.CharField(max_length=80, default="security_validation")
    authorization_id = models.CharField(max_length=200)
    environment = models.CharField(max_length=80, default="lab")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNED)
    scope = models.JSONField(default=dict)
    capabilities = models.JSONField(default=list)
    authorization_evidence = models.JSONField(default=dict, blank=True)
    baseline = models.JSONField(default=dict, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    terminal_reason = models.TextField(blank=True)
    cleanup_status = models.CharField(
        max_length=20, choices=CleanupStatus.choices, default=CleanupStatus.NOT_STARTED
    )
    started_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["project", "status"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["authorization_id"]),
        ]

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            self.Status.COMPLETED,
            self.Status.FAILED,
            self.Status.EXPIRED,
            self.Status.REVOKED,
        }


class ExecutionIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.OneToOneField(
        SecurityTestSession, on_delete=models.CASCADE, related_name="execution_identity"
    )
    identity_ref = models.CharField(max_length=160, unique=True)
    token_prefix = models.CharField(max_length=24)
    token_hash = models.CharField(max_length=64, unique=True)
    issued_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    capabilities = models.JSONField(default=list)
    claims = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["revoked_at"]),
        ]

    @property
    def active(self) -> bool:
        return self.revoked_at is None and timezone.now() < self.expires_at


class EvidenceRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    session = models.ForeignKey(
        SecurityTestSession, on_delete=models.CASCADE, related_name="evidence_records"
    )
    sequence = models.PositiveBigIntegerField()
    event_type = models.CharField(max_length=100)
    capability = models.CharField(max_length=80, blank=True)
    target = models.CharField(max_length=500, blank=True)
    action = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=40, default="observed")
    artifact_ref = models.CharField(max_length=500, blank=True)
    data = models.JSONField(default=dict, blank=True)
    content_hash = models.CharField(max_length=64)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["sequence"]
        constraints = [
            models.UniqueConstraint(fields=["session", "sequence"], name="uniq_session_evidence_sequence")
        ]
        indexes = [
            models.Index(fields=["session", "sequence"]),
            models.Index(fields=["session", "event_type"]),
            models.Index(fields=["event_hash"]),
        ]
