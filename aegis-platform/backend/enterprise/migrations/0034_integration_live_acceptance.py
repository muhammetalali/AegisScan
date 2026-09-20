from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0033_agom_governed_action_requests'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='IntegrationAcceptanceTest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('test_type', models.CharField(default='live_probe', max_length=80)),
                ('outcome', models.CharField(choices=[('passed', 'Passed'), ('failed', 'Failed')], max_length=20)),
                ('source_ref', models.CharField(max_length=255)),
                ('evidence_sha256', models.CharField(max_length=64)),
                ('evidence_summary', models.JSONField(blank=True, default=dict)),
                ('configuration_fingerprint', models.CharField(max_length=64)),
                ('test_fingerprint', models.CharField(max_length=64)),
                ('tested_at', models.DateTimeField(auto_now_add=True)),
                ('integration', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='acceptance_tests', to='enterprise.externalintegration')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_acceptance_tests', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_acceptance_tests', to='projects.project')),
                ('tested_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_acceptance_tests', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddConstraint(
            model_name='integrationacceptancetest',
            constraint=models.UniqueConstraint(fields=('organization', 'test_fingerprint'), name='uniq_integration_test_fingerprint'),
        ),
        migrations.AddConstraint(
            model_name='integrationacceptancetest',
            constraint=models.UniqueConstraint(fields=('integration', 'project', 'source_ref'), name='uniq_integration_test_source'),
        ),
        migrations.AddIndex(
            model_name='integrationacceptancetest',
            index=models.Index(fields=['integration', 'project', 'tested_at'], name='idx_integration_test_time'),
        ),
        migrations.AddIndex(
            model_name='integrationacceptancetest',
            index=models.Index(fields=['organization', 'outcome'], name='idx_integration_test_outcome'),
        ),
        migrations.CreateModel(
            name='IntegrationLiveAcceptance',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('vendor_ack', models.CharField(max_length=500)),
                ('acceptance_evidence_sha256', models.CharField(max_length=64)),
                ('review_at', models.DateTimeField()),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('acceptance_fingerprint', models.CharField(max_length=64)),
                ('accepted_at', models.DateTimeField(auto_now_add=True)),
                ('acceptance_test', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='live_acceptance', to='enterprise.integrationacceptancetest')),
                ('accepted_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_live_acceptances', to=settings.AUTH_USER_MODEL)),
                ('integration', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='live_acceptances', to='enterprise.externalintegration')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_live_acceptances', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='integration_live_acceptances', to='projects.project')),
                ('supersedes', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='superseded_by', to='enterprise.integrationliveacceptance')),
            ],
        ),
        migrations.AddConstraint(
            model_name='integrationliveacceptance',
            constraint=models.UniqueConstraint(fields=('organization', 'acceptance_fingerprint'), name='uniq_integration_accept_fingerprint'),
        ),
        migrations.AddIndex(
            model_name='integrationliveacceptance',
            index=models.Index(fields=['integration', 'project', 'accepted_at'], name='idx_integration_accept_time'),
        ),
        migrations.AddIndex(
            model_name='integrationliveacceptance',
            index=models.Index(fields=['organization', 'review_at'], name='idx_integration_accept_review'),
        ),
    ]
