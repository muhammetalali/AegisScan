# Generated manually for the Security Test Session control plane.

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("projects", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="SecurityTestSession",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("assessment_type", models.CharField(default="security_validation", max_length=80)),
                ("authorization_id", models.CharField(max_length=200)),
                ("environment", models.CharField(default="lab", max_length=80)),
                ("status", models.CharField(choices=[("planned", "Planned"), ("active", "Active"), ("suspended", "Suspended"), ("completing", "Completing"), ("completed", "Completed"), ("failed", "Failed"), ("expired", "Expired"), ("revoked", "Revoked")], default="planned", max_length=20)),
                ("scope", models.JSONField(default=dict)),
                ("capabilities", models.JSONField(default=list)),
                ("authorization_evidence", models.JSONField(blank=True, default=dict)),
                ("baseline", models.JSONField(blank=True, default=dict)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("terminal_reason", models.TextField(blank=True)),
                ("cleanup_status", models.CharField(choices=[("not_started", "Not Started"), ("running", "Running"), ("verified", "Verified"), ("partial", "Partial"), ("failed", "Failed")], default="not_started", max_length=20)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("expires_at", models.DateTimeField()),
                ("ended_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("initiated_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="initiated_security_test_sessions", to=settings.AUTH_USER_MODEL)),
                ("project", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="security_test_sessions", to="projects.project")),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="ExecutionIdentity",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("identity_ref", models.CharField(max_length=160, unique=True)),
                ("token_prefix", models.CharField(max_length=24)),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("issued_at", models.DateTimeField(default=timezone.now)),
                ("expires_at", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("last_seen_at", models.DateTimeField(blank=True, null=True)),
                ("capabilities", models.JSONField(default=list)),
                ("claims", models.JSONField(blank=True, default=dict)),
                ("session", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="execution_identity", to="security_sessions.securitytestsession")),
            ],
        ),
        migrations.CreateModel(
            name="EvidenceRecord",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("sequence", models.PositiveBigIntegerField()),
                ("event_type", models.CharField(max_length=100)),
                ("capability", models.CharField(blank=True, max_length=80)),
                ("target", models.CharField(blank=True, max_length=500)),
                ("action", models.CharField(blank=True, max_length=200)),
                ("status", models.CharField(default="observed", max_length=40)),
                ("artifact_ref", models.CharField(blank=True, max_length=500)),
                ("data", models.JSONField(blank=True, default=dict)),
                ("content_hash", models.CharField(max_length=64)),
                ("previous_hash", models.CharField(blank=True, max_length=64)),
                ("event_hash", models.CharField(max_length=64, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="evidence_records", to="security_sessions.securitytestsession")),
            ],
            options={"ordering": ["sequence"]},
        ),
        migrations.AddIndex(model_name="securitytestsession", index=models.Index(fields=["project", "status"], name="security_se_project_6f6af2_idx")),
        migrations.AddIndex(model_name="securitytestsession", index=models.Index(fields=["expires_at"], name="security_se_expires_2c4b6c_idx")),
        migrations.AddIndex(model_name="securitytestsession", index=models.Index(fields=["authorization_id"], name="security_se_authoriz_6e5d79_idx")),
        migrations.AddIndex(model_name="executionidentity", index=models.Index(fields=["expires_at"], name="security_ex_expires_00c3c5_idx")),
        migrations.AddIndex(model_name="executionidentity", index=models.Index(fields=["revoked_at"], name="security_ex_revoked_5c4252_idx")),
        migrations.AddConstraint(model_name="evidencerecord", constraint=models.UniqueConstraint(fields=("session", "sequence"), name="uniq_session_evidence_sequence")),
        migrations.AddIndex(model_name="evidencerecord", index=models.Index(fields=["session", "sequence"], name="security_ev_session__b9dc4b_idx")),
        migrations.AddIndex(model_name="evidencerecord", index=models.Index(fields=["session", "event_type"], name="security_ev_session__68cb9d_idx")),
        migrations.AddIndex(model_name="evidencerecord", index=models.Index(fields=["event_hash"], name="security_ev_event_ha_91cb42_idx")),
    ]
