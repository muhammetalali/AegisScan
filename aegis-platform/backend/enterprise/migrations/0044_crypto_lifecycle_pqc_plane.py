from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0043_crypto_asset_cbom_plane'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CryptoLifecycleAssessment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('assessment_version', models.PositiveIntegerField()),
                ('lifecycle_state', models.CharField(choices=[('compliant', 'Compliant'), ('action_required', 'Action Required'), ('critical', 'Critical')], max_length=24)),
                ('pqc_readiness', models.CharField(choices=[('ready', 'PQC Ready'), ('hybrid', 'Hybrid Transition'), ('transition_required', 'Transition Required'), ('unknown', 'Unknown')], max_length=24)),
                ('total_records', models.PositiveIntegerField(default=0)),
                ('weak_deprecated_count', models.PositiveIntegerField(default=0)),
                ('expired_count', models.PositiveIntegerField(default=0)),
                ('expiring_30d_count', models.PositiveIntegerField(default=0)),
                ('expiring_90d_count', models.PositiveIntegerField(default=0)),
                ('quantum_vulnerable_count', models.PositiveIntegerField(default=0)),
                ('quantum_resistant_count', models.PositiveIntegerField(default=0)),
                ('hybrid_count', models.PositiveIntegerField(default=0)),
                ('policy_snapshot', models.JSONField(default=dict)),
                ('migration_plan', models.JSONField(default=dict)),
                ('assessment_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='crypto-lifecycle-pqc.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_lifecycle_assessments', to='assets.asset')),
                ('evaluated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_lifecycle_assessments', to=settings.AUTH_USER_MODEL)),
                ('inventory_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='lifecycle_assessments', to='enterprise.cryptographicinventorysnapshot')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_lifecycle_assessments', to='enterprise.organization')),
                ('predecessor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='successors', to='enterprise.cryptolifecycleassessment')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_lifecycle_assessments', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', '-assessment_version'], name='idx_crypto_lifecycle_latest'),
                    models.Index(fields=['lifecycle_state', 'pqc_readiness'], name='idx_crypto_lifecycle_state'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('project', 'asset', 'assessment_version'), name='uniq_crypto_lifecycle_asset_version'),
                ],
            },
        ),
    ]
