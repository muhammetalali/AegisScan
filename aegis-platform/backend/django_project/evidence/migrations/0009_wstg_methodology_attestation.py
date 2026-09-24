# Generated for immutable governed WSTG methodology completion attestations.

import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('evidence', '0008_governed_oast_runtime'),
        ('enterprise', '0031_agom_evidence_qualification'),
        ('projects', '0003_governed_scheduled_scan'),
        ('scans', '0004_governed_execution_contract'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='WSTGMethodologyAttestation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('wstg_id', models.CharField(max_length=64)),
                ('classification', models.CharField(max_length=32)),
                ('completion_mode', models.CharField(max_length=48)),
                ('decision', models.CharField(choices=[('completed', 'Completed'), ('not_applicable', 'Not Applicable')], max_length=24)),
                ('evidence_ids', models.JSONField(default=list)),
                ('rationale', models.TextField()),
                ('policy_version', models.CharField(default='wstg-completion.v1', max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='wstg_methodology_attestations', to=settings.AUTH_USER_MODEL)),
                ('evidence_qualification', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='wstg_methodology_attestations', to='enterprise.evidencequalificationevaluation')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='wstg_methodology_attestations', to='projects.project')),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='wstg_methodology_attestations', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'wstg_id', '-created_at'], name='idx_wstg_attest_project'),
                    models.Index(fields=['scan', 'wstg_id', '-created_at'], name='idx_wstg_attest_scan'),
                ],
            },
        ),
    ]
