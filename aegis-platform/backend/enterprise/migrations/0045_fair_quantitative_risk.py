from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0044_crypto_lifecycle_pqc_plane'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FAIRQuantitativeRiskAnalysis',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('analysis_version', models.PositiveIntegerField()),
                ('simulation_iterations', models.PositiveIntegerField()),
                ('simulation_seed', models.PositiveBigIntegerField()),
                ('currency', models.CharField(default='USD', max_length=3)),
                ('assumptions', models.JSONField(default=dict)),
                ('assumption_evidence', models.JSONField(default=dict)),
                ('evidence_snapshot', models.JSONField(default=list)),
                ('assumptions_sha256', models.CharField(editable=False, max_length=64)),
                ('evidence_sha256', models.CharField(editable=False, max_length=64)),
                ('loss_event_frequency_mean', models.FloatField()),
                ('annual_loss_mean', models.DecimalField(decimal_places=2, max_digits=24)),
                ('annual_loss_p50', models.DecimalField(decimal_places=2, max_digits=24)),
                ('annual_loss_p95', models.DecimalField(decimal_places=2, max_digits=24)),
                ('result_summary', models.JSONField(default=dict)),
                ('result_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='fair-quantitative-risk.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('analyzed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='fair_risk_analyses', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='fair_risk_analyses', to='enterprise.organization')),
                ('predecessor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='successors', to='enterprise.fairquantitativeriskanalysis')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='fair_risk_analyses', to='projects.project')),
                ('risk_correlation', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='fair_risk_analyses', to='enterprise.riskcorrelationsnapshot')),
                ('vulnerability', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='fair_risk_analyses', to='vulnerabilities.vulnerability')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'vulnerability', '-analysis_version'], name='idx_fair_risk_latest'),
                    models.Index(fields=['risk_correlation', '-created_at'], name='idx_fair_risk_correlation'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('project', 'vulnerability', 'analysis_version'), name='uniq_fair_risk_finding_version'),
                ],
            },
        ),
    ]
