from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('audit', '0006_alter_auditlog_action'),
        ('enterprise', '0029_agom_governed_responsibilities'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedActionExecution',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action_id', models.CharField(max_length=128)),
                ('entity_type', models.CharField(max_length=80)),
                ('entity_id', models.CharField(max_length=128)),
                ('expected_version', models.PositiveIntegerField()),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('contract_version', models.CharField(default='agom.v1', max_length=32)),
                ('contract_policy_version', models.CharField(max_length=64)),
                ('evaluation_policy_version', models.CharField(max_length=64)),
                ('policy_fingerprint', models.CharField(editable=False, max_length=64)),
                ('correlation_id', models.UUIDField(default=uuid.uuid4, editable=False)),
                ('request_payload', models.JSONField(default=dict)),
                ('before_projection', models.JSONField(default=dict)),
                ('gate_snapshot', models.JSONField(default=list)),
                ('result_payload', models.JSONField(default=dict)),
                ('after_projection', models.JSONField(default=dict)),
                ('execution_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_executions', to=settings.AUTH_USER_MODEL)),
                ('audit_log', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_execution', to='audit.auditlog')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_executions', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_executions', to='projects.project')),
            ],
            options={'ordering': ['-created_at', '-id']},
        ),
        migrations.AddConstraint(
            model_name='governedactionexecution',
            constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govact_org_idem'),
        ),
        migrations.AddIndex(
            model_name='governedactionexecution',
            index=models.Index(fields=['organization', 'action_id', '-created_at'], name='idx_govact_org_action'),
        ),
        migrations.AddIndex(
            model_name='governedactionexecution',
            index=models.Index(fields=['project', 'entity_type', 'entity_id'], name='idx_govact_project_entity'),
        ),
        migrations.AddIndex(
            model_name='governedactionexecution',
            index=models.Index(fields=['correlation_id'], name='idx_govact_correlation'),
        ),
    ]
