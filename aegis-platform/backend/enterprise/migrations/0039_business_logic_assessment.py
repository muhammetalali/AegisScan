from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0038_attack_path_validation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BusinessLogicAssessment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action_id', models.CharField(max_length=128)),
                ('entity_type', models.CharField(max_length=80)),
                ('entity_id', models.CharField(max_length=128)),
                ('request_fingerprint', models.CharField(max_length=64)),
                ('contract_fingerprint', models.CharField(max_length=64)),
                ('evaluation_policy_version', models.CharField(max_length=64)),
                ('projection_snapshot', models.JSONField(default=dict)),
                ('capability_snapshot', models.JSONField(default=dict)),
                ('invariant_results', models.JSONField(default=list)),
                ('decision', models.CharField(choices=[('passed', 'Passed'), ('blocked', 'Blocked')], max_length=16)),
                ('reason_codes', models.JSONField(default=list)),
                ('assessment_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('assessed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='business_logic_assessments', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='business_logic_assessments', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='business_logic_assessments', to='projects.project')),
                ('request', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='business_logic_assessments', to='enterprise.governedactionrequest')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'decision', '-created_at'], name='idx_bizlogic_project_dec'),
                    models.Index(fields=['request', '-created_at'], name='idx_bizlogic_request_time'),
                ],
            },
        ),
    ]
