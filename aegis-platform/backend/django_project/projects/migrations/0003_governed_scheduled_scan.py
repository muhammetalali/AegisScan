from django.db import migrations, models
import django.db.models.deletion
import uuid


def disable_legacy_schedules(apps, schema_editor):
    ScheduledScan = apps.get_model('projects', 'ScheduledScan')
    ScheduledScan.objects.filter(is_active=True).update(
        is_active=False,
        disabled_reason='Legacy schedule requires canonical asset/capability binding.',
    )


class Migration(migrations.Migration):
    dependencies = [
        ('projects', '0002_initial'),
        ('assets', '0007_authorization_request_identity'),
        ('scans', '0004_governed_execution_contract'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scheduledscan',
            name='template',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='scheduled_scans',
                to='projects.scantemplate',
            ),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='asset',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='scheduled_scans',
                to='assets.asset',
            ),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='capability_id',
            field=models.CharField(blank=True, max_length=120),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='depth',
            field=models.CharField(
                choices=[
                    ('quick', 'Quick'),
                    ('standard', 'Standard'),
                    ('deep', 'Deep'),
                    ('comprehensive', 'Comprehensive'),
                ],
                default='standard',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='options',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='credential_refs',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='policy_version',
            field=models.CharField(default='scheduled-capability.v1', max_length=64),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='timezone',
            field=models.CharField(default='UTC', max_length=64),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='disabled_reason',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='scheduledscan',
            name='version',
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AddIndex(
            model_name='scheduledscan',
            index=models.Index(fields=['is_active', 'next_run'], name='idx_schedscan_due'),
        ),
        migrations.AddIndex(
            model_name='scheduledscan',
            index=models.Index(fields=['project', 'capability_id'], name='idx_schedscan_cap'),
        ),
        migrations.RunPython(disable_legacy_schedules, migrations.RunPython.noop),
        migrations.CreateModel(
            name='ScheduledScanExecution',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scheduled_for', models.DateTimeField()),
                ('schedule_version', models.PositiveIntegerField()),
                ('actor_id_snapshot', models.CharField(max_length=64)),
                ('capability_id', models.CharField(max_length=120)),
                ('depth_snapshot', models.CharField(max_length=20)),
                ('options_snapshot', models.JSONField(default=dict)),
                ('credential_refs_snapshot', models.JSONField(default=list)),
                ('policy_version_snapshot', models.CharField(max_length=64)),
                ('target_snapshot', models.CharField(blank=True, max_length=500)),
                ('request_fingerprint', models.CharField(max_length=64)),
                ('policy_fingerprint', models.CharField(blank=True, max_length=64)),
                ('execution_contract_fingerprint', models.CharField(blank=True, max_length=64)),
                ('idempotency_key', models.CharField(max_length=128)),
                ('correlation_id', models.CharField(max_length=128)),
                ('status', models.CharField(choices=[('claimed', 'Claimed'), ('running', 'Running'), ('dispatched', 'Dispatched'), ('blocked', 'Blocked'), ('failed', 'Failed')], default='claimed', max_length=20)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('celery_task_id', models.CharField(blank=True, max_length=255)),
                ('scanner_task_id', models.CharField(blank=True, max_length=255)),
                ('reason', models.TextField(blank=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('dispatched_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='scheduled_scan_executions', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='scheduled_scan_executions', to='assets.assetauthorization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='scheduled_scan_executions', to='projects.project')),
                ('scan', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='scheduled_execution', to='scans.scan')),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='executions', to='projects.scheduledscan')),
            ],
            options={
                'ordering': ['-scheduled_for', '-created_at'],
                'indexes': [
                    models.Index(fields=['status', 'created_at'], name='idx_schedexec_status'),
                    models.Index(fields=['schedule', 'scheduled_for'], name='idx_schedexec_occurrence'),
                    models.Index(fields=['project', 'correlation_id'], name='idx_schedexec_corr'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('schedule', 'scheduled_for'), name='uniq_schedscan_occurrence'),
                ],
            },
        ),
    ]
