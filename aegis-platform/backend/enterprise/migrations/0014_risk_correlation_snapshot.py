import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0013_external_integration_fabric'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='RiskCorrelationSnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('analysis_version', models.CharField(default='1.0', max_length=20)),
                ('score', models.FloatField()),
                ('priority', models.CharField(
                    choices=[
                        ('P0-CRITICAL', 'P0 Critical'),
                        ('P1-HIGH', 'P1 High'),
                        ('P2-MEDIUM', 'P2 Medium'),
                        ('P3-LOW', 'P3 Low'),
                    ],
                    max_length=20,
                )),
                ('components', models.JSONField(default=dict)),
                ('evidence_count', models.PositiveIntegerField(default=0)),
                ('source_snapshot_sha256', models.CharField(max_length=64)),
                ('correlation_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('attack_path', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name='risk_correlation_snapshots',
                    to='enterprise.attackpath',
                )),
                ('created_by', models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name='risk_correlation_snapshots',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('finding_intelligence', models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name='risk_correlation_snapshots',
                    to='enterprise.findingintelligence',
                )),
                ('project', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='risk_correlation_snapshots',
                    to='projects.project',
                )),
                ('source_snapshot', models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name='risk_correlation_snapshots',
                    to='intelligence.intelligenceenrichment',
                )),
                ('vulnerability', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='risk_correlation_snapshots',
                    to='vulnerabilities.vulnerability',
                )),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'priority', '-created_at'], name='idx_riskcorr_project_prio'),
                    models.Index(fields=['vulnerability', '-created_at'], name='idx_riskcorr_finding_time'),
                    models.Index(fields=['source_snapshot', '-created_at'], name='idx_riskcorr_source_time'),
                ],
            },
        ),
    ]
