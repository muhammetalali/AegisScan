from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0032_agom_global_time_exception_policy'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedActionRequest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action_id', models.CharField(max_length=128)),
                ('entity_type', models.CharField(max_length=80)),
                ('entity_id', models.CharField(max_length=128)),
                ('expected_version', models.PositiveIntegerField()),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('contract_version', models.CharField(max_length=32)),
                ('contract_policy_version', models.CharField(max_length=64)),
                ('contract_snapshot', models.JSONField(default=dict)),
                ('contract_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('correlation_id', models.UUIDField(default=uuid.uuid4, editable=False)),
                ('parameters_snapshot', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_requests', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_requests', to='projects.project')),
                ('requested_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_action_requests', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at', '-id']},
        ),
        migrations.AddConstraint(
            model_name='governedactionrequest',
            constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govreq_org_idem'),
        ),
        migrations.AddIndex(
            model_name='governedactionrequest',
            index=models.Index(fields=['organization', 'action_id', '-created_at'], name='idx_govreq_org_action'),
        ),
        migrations.AddIndex(
            model_name='governedactionrequest',
            index=models.Index(fields=['project', 'entity_type', 'entity_id'], name='idx_govreq_project_entity'),
        ),
        migrations.AddIndex(
            model_name='governedactionrequest',
            index=models.Index(fields=['correlation_id'], name='idx_govreq_correlation'),
        ),
        migrations.AddField(
            model_name='governedactionexecution',
            name='request',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='execution', to='enterprise.governedactionrequest'),
        ),
    ]
