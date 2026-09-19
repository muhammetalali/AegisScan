from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0031_agom_evidence_qualification'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedTemporalException',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('kind', models.CharField(choices=[('exception', 'Exception'), ('waiver', 'Waiver')], max_length=20)),
                ('scope_kind', models.CharField(choices=[('project', 'Project'), ('entity_type', 'Entity Type'), ('entity', 'Entity'), ('action', 'Action')], max_length=20)),
                ('action_id', models.CharField(blank=True, max_length=128)),
                ('entity_type', models.CharField(blank=True, max_length=80)),
                ('entity_id', models.CharField(blank=True, max_length=128)),
                ('effective_from', models.DateTimeField()),
                ('expires_at', models.DateTimeField()),
                ('review_at', models.DateTimeField(blank=True, null=True)),
                ('grace_period_seconds', models.PositiveIntegerField(default=0)),
                ('escalation_level', models.PositiveIntegerField(default=0)),
                ('recurrence', models.JSONField(blank=True, default=dict)),
                ('reason', models.TextField()),
                ('policy_version', models.CharField(default='agom-temporal.v1', max_length=64)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('grant_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('issued_at', models.DateTimeField(auto_now_add=True)),
                ('issued_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='issued_governed_temporal_exceptions', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_exceptions', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_exceptions', to='projects.project')),
                ('renewal_of', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='renewals', to='enterprise.governedtemporalexception')),
                ('supersedes', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='superseded_by', to='enterprise.governedtemporalexception')),
            ],
            options={'ordering': ['-issued_at', '-id']},
        ),
        migrations.CreateModel(
            name='GovernedTemporalExceptionRevocation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('reason', models.TextField()),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('revocation_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('revoked_at', models.DateTimeField(auto_now_add=True)),
                ('exception', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='revocation', to='enterprise.governedtemporalexception')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_exception_revocations', to='enterprise.organization')),
                ('revoked_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='revoked_governed_temporal_exceptions', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-revoked_at', '-id']},
        ),
        migrations.CreateModel(
            name='GovernedTemporalEvaluation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action_id', models.CharField(max_length=128)),
                ('entity_type', models.CharField(max_length=80)),
                ('entity_id', models.CharField(max_length=128)),
                ('effective_from', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('review_at', models.DateTimeField(blank=True, null=True)),
                ('grace_period_seconds', models.PositiveIntegerField(default=0)),
                ('renewal_ref', models.CharField(blank=True, max_length=128)),
                ('recurrence', models.JSONField(blank=True, default=dict)),
                ('escalation_level', models.PositiveIntegerField(default=0)),
                ('decision', models.CharField(choices=[('active', 'Active'), ('not_yet_effective', 'Not Yet Effective'), ('expired', 'Expired'), ('grace_active', 'Grace Active'), ('review_due', 'Review Due'), ('exception_active', 'Exception Active'), ('waiver_active', 'Waiver Active'), ('hard_blocked', 'Hard Blocked')], max_length=32)),
                ('allowed', models.BooleanField(default=False)),
                ('reason_codes', models.JSONField(default=list)),
                ('reasons', models.JSONField(default=list)),
                ('hard_blocks', models.JSONField(default=list)),
                ('policy_version', models.CharField(max_length=64)),
                ('policy_snapshot', models.JSONField(default=dict)),
                ('evaluation_context', models.JSONField(default=dict)),
                ('evaluation_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('evaluated_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('exception', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='evaluations', to='enterprise.governedtemporalexception')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_evaluations', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_evaluations', to='projects.project')),
                ('requested_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governed_temporal_evaluations', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-evaluated_at', '-id']},
        ),
        migrations.AddConstraint(
            model_name='governedtemporalexception',
            constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govtemp_exception_idem'),
        ),
        migrations.AddConstraint(
            model_name='governedtemporalexception',
            constraint=models.CheckConstraint(condition=models.Q(('expires_at__gt', models.F('effective_from'))), name='govtemp_exception_valid_window'),
        ),
        migrations.AddConstraint(
            model_name='governedtemporalexception',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(('action_id', ''), ('entity_id', ''), ('entity_type', ''), ('scope_kind', 'project'))
                    | (models.Q(('action_id', ''), ('entity_id', ''), ('scope_kind', 'entity_type')) & ~models.Q(('entity_type', '')))
                    | (models.Q(('action_id', ''), ('scope_kind', 'entity')) & ~models.Q(('entity_type', '')) & ~models.Q(('entity_id', '')))
                    | (models.Q(('scope_kind', 'action')) & ~models.Q(('action_id', '')))
                ),
                name='govtemp_exception_scope_shape',
            ),
        ),
        migrations.AddConstraint(
            model_name='governedtemporalexception',
            constraint=models.CheckConstraint(condition=models.Q(('renewal_of__isnull', True)) | models.Q(('supersedes__isnull', True)), name='govtemp_exception_single_lineage_mode'),
        ),
        migrations.AddIndex(
            model_name='governedtemporalexception',
            index=models.Index(fields=['organization', 'project', 'expires_at'], name='idx_govtemp_scope_expiry'),
        ),
        migrations.AddIndex(
            model_name='governedtemporalexception',
            index=models.Index(fields=['project', 'action_id', 'entity_type'], name='idx_govtemp_action_entity'),
        ),
        migrations.AddConstraint(
            model_name='governedtemporalexceptionrevocation',
            constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govtemp_revoke_idem'),
        ),
        migrations.AddConstraint(
            model_name='governedtemporalevaluation',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(('allowed', True), ('decision__in', ['active', 'grace_active', 'exception_active', 'waiver_active']))
                    | models.Q(('allowed', False), ('decision__in', ['not_yet_effective', 'expired', 'review_due', 'hard_blocked']))
                ),
                name='govtemp_eval_decision_allowed',
            ),
        ),
        migrations.AddIndex(
            model_name='governedtemporalevaluation',
            index=models.Index(fields=['organization', 'decision', '-evaluated_at'], name='idx_govtemp_eval_org_dec'),
        ),
        migrations.AddIndex(
            model_name='governedtemporalevaluation',
            index=models.Index(fields=['project', 'action_id', '-evaluated_at'], name='idx_govtemp_eval_action'),
        ),
        migrations.AddIndex(
            model_name='governedtemporalevaluation',
            index=models.Index(fields=['entity_type', 'entity_id', '-evaluated_at'], name='idx_govtemp_eval_entity'),
        ),
    ]
