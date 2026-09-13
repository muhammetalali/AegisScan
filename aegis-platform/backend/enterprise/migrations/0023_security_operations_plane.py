import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('enterprise', '0022_detection_as_code_plane'),
        ('projects', '0002_initial'),
        ('vulnerabilities', '0002_delete_vulnerabilityevidence'),
    ]

    operations = [
        migrations.CreateModel(
            name='SecuritySignal',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('fingerprint', models.CharField(max_length=64, unique=True)),
                ('severity', models.CharField(max_length=20)),
                ('attack_techniques', models.JSONField(default=list)),
                ('payload_sha256', models.CharField(max_length=64)),
                ('observed_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_security_signals', to=settings.AUTH_USER_MODEL)),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='security_signals', to='vulnerabilities.vulnerability')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='security_signals', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='security_signals', to='projects.project')),
                ('revision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='security_signals', to='enterprise.detectionrevision')),
                ('validation', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='security_signal', to='enterprise.detectionvalidation')),
            ],
            options={
                'ordering': ['-observed_at', '-created_at'],
                'indexes': [models.Index(fields=['project', '-observed_at'], name='idx_soc_signal_project_time'), models.Index(fields=['finding', '-observed_at'], name='idx_soc_signal_finding_time')],
            },
        ),
        migrations.CreateModel(
            name='InvestigationCaseState',
            fields=[
                ('case', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='soc_state', serialize=False, to='enterprise.investigationcase')),
                ('correlation_key', models.CharField(max_length=64, unique=True)),
                ('version', models.PositiveIntegerField(default=1)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('decision_action', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='investigation_cases', to='enterprise.decisionaction')),
            ],
            options={'indexes': [models.Index(fields=['decision_action'], name='idx_soc_case_decision_action')]},
        ),
        migrations.CreateModel(
            name='InvestigationSignalLink',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('linked_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='signal_links', to='enterprise.investigationcase')),
                ('linked_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='investigation_signal_links', to=settings.AUTH_USER_MODEL)),
                ('signal', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='case_link', to='enterprise.securitysignal')),
            ],
            options={'indexes': [models.Index(fields=['case', '-linked_at'], name='idx_soc_case_signal_time')], 'constraints': [models.UniqueConstraint(fields=('case', 'signal'), name='uniq_soc_case_signal')]},
        ),
        migrations.CreateModel(
            name='InvestigationAuditEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=80)),
                ('payload', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, max_length=64)),
                ('entry_hash', models.CharField(max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='investigation_soc_events', to=settings.AUTH_USER_MODEL)),
                ('case', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='soc_events', to='enterprise.investigationcase')),
            ],
            options={'ordering': ['id'], 'indexes': [models.Index(fields=['case', 'id'], name='idx_soc_case_event')]},
        ),
    ]
