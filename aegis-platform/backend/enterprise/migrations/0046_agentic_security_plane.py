from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0045_fair_quantitative_risk'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AgenticSecurityProfile',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('agent_name', models.CharField(max_length=180)),
                ('agent_version', models.CharField(max_length=120)),
                ('model_name', models.CharField(max_length=180)),
                ('model_version', models.CharField(max_length=120)),
                ('provider_name', models.CharField(max_length=180)),
                ('provider_version', models.CharField(max_length=120)),
                ('capability', models.CharField(default='ai.agent.runtime', max_length=180)),
                ('allowed_tools', models.JSONField(default=dict)),
                ('data_boundaries', models.JSONField(default=dict)),
                ('prompt_policy', models.JSONField(default=dict)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('profile_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='agentic-security.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_agentic_security_profiles', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_security_profiles', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_security_profiles', to='projects.project')),
                ('provider_governance_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_security_profiles', to='enterprise.providerapprovaldecision')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'agent_name', '-created_at'], name='idx_agentic_profile_project'),
                    models.Index(fields=['provider_governance_decision', '-created_at'], name='idx_agentic_profile_provider'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_agentic_profile_org_idem'),
                ],
            },
        ),
        migrations.CreateModel(
            name='AgenticActionDecision',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('tool_name', models.CharField(max_length=180)),
                ('operation', models.CharField(max_length=180)),
                ('prompt_sha256', models.CharField(max_length=64)),
                ('prompt_length', models.PositiveIntegerField()),
                ('arguments_sha256', models.CharField(max_length=64)),
                ('argument_keys', models.JSONField(default=list)),
                ('data_labels', models.JSONField(default=list)),
                ('risk_signals', models.JSONField(default=list)),
                ('human_approval_ref', models.CharField(blank=True, max_length=255)),
                ('decision', models.CharField(choices=[('allowed', 'Allowed'), ('denied', 'Denied')], max_length=16)),
                ('reason_codes', models.JSONField(default=list)),
                ('evidence_snapshot', models.JSONField(default=dict)),
                ('evidence_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('decision_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='agentic-security.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('decided_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_action_decisions', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_action_decisions', to='enterprise.organization')),
                ('profile', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='action_decisions', to='enterprise.agenticsecurityprofile')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='agentic_action_decisions', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'decision', '-created_at'], name='idx_agentic_action_project'),
                    models.Index(fields=['profile', '-created_at'], name='idx_agentic_action_profile'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('profile', 'idempotency_key'), name='uniq_agentic_action_profile_idem'),
                ],
            },
        ),
    ]
