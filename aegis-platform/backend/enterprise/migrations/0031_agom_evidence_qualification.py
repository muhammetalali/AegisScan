from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0030_agom_governed_action_execution'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='EvidenceQualificationEvaluation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('subject_type', models.CharField(max_length=80)),
                ('subject_id', models.CharField(max_length=128)),
                ('target', models.CharField(blank=True, max_length=500)),
                ('authorization_ref', models.CharField(blank=True, max_length=128)),
                ('execution_ref', models.CharField(blank=True, max_length=128)),
                ('policy_version', models.CharField(max_length=64)),
                ('policy_snapshot', models.JSONField(default=dict)),
                ('requested_evidence_ids', models.JSONField(default=list)),
                ('evidence_snapshot', models.JSONField(default=list)),
                ('evidence_set_hash', models.CharField(db_index=True, max_length=64)),
                ('decision', models.CharField(choices=[('qualified', 'Qualified'), ('not_authorized', 'Not Authorized'), ('stale', 'Stale'), ('expired', 'Expired'), ('revoked', 'Revoked'), ('contradicted', 'Contradicted'), ('superseded', 'Superseded'), ('wrong_subject', 'Wrong Subject'), ('wrong_tenant', 'Wrong Tenant'), ('wrong_project', 'Wrong Project'), ('wrong_execution', 'Wrong Execution'), ('wrong_target', 'Wrong Target'), ('missing_provenance', 'Missing Provenance'), ('insufficient_evidence', 'Insufficient Evidence'), ('integrity_mismatch', 'Integrity Mismatch'), ('replayed_evidence', 'Replayed Evidence')], max_length=40)),
                ('qualified', models.BooleanField(default=False)),
                ('reason_codes', models.JSONField(default=list)),
                ('reasons', models.JSONField(default=list)),
                ('evaluation_context', models.JSONField(default=dict)),
                ('evaluation_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('evaluated_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='evidence_qualification_evaluations', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='evidence_qualification_evaluations', to='projects.project')),
                ('requested_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='evidence_qualification_evaluations', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-evaluated_at', '-id']},
        ),
        migrations.AddIndex(
            model_name='evidencequalificationevaluation',
            index=models.Index(fields=['organization', 'decision', '-evaluated_at'], name='idx_evidqual_org_decision'),
        ),
        migrations.AddIndex(
            model_name='evidencequalificationevaluation',
            index=models.Index(fields=['project', 'subject_type', 'subject_id'], name='idx_evidqual_project_subject'),
        ),
        migrations.AddIndex(
            model_name='evidencequalificationevaluation',
            index=models.Index(fields=['policy_version', '-evaluated_at'], name='idx_evidqual_policy_time'),
        ),
        migrations.AddConstraint(
            model_name='evidencequalificationevaluation',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(decision='qualified', qualified=True)
                    | (~models.Q(decision='qualified') & models.Q(qualified=False))
                ),
                name='evidqual_decision_matches_bool',
            ),
        ),
    ]
