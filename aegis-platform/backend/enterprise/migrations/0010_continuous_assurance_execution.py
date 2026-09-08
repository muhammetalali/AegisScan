import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0007_authorization_request_identity'),
        ('enterprise', '0009_decision_action_tenant_lineage'),
        ('projects', '0002_initial'),
        ('scans', '0003_scan_authorization_decision'),
    ]

    operations = [
        migrations.AddField(
            model_name='continuousassuranceschedule', name='disabled_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='continuousassuranceschedule', name='disabled_reason',
            field=models.TextField(blank=True),
        ),
        migrations.CreateModel(
            name='ContinuousAssuranceExecution',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scheduled_for', models.DateTimeField()),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('queued', 'Queued'), ('completed', 'Completed'), ('blocked', 'Blocked'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('celery_task_id', models.CharField(blank=True, max_length=255)),
                ('scanner_task_id', models.CharField(blank=True, max_length=255)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('reason', models.TextField(blank=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_executions', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_executions', to='assets.assetauthorization')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_executions', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_executions', to='projects.project')),
                ('scan', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_execution', to='scans.scan')),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='executions', to='enterprise.continuousassuranceschedule')),
            ],
            options={
                'indexes': [models.Index(fields=['schedule', 'status'], name='idx_assurance_schedule_state'), models.Index(fields=['organization', 'status'], name='idx_assurance_org_state')],
                'constraints': [models.UniqueConstraint(fields=('schedule', 'scheduled_for'), name='uniq_assurance_schedule_occurrence')],
            },
        ),
    ]
