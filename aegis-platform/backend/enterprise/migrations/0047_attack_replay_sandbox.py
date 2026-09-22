from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0046_agentic_security_plane'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackReplayScenario',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('isolation_contract', models.JSONField(default=dict)),
                ('source_snapshot', models.JSONField(default=dict)),
                ('expected_controls', models.JSONField(default=list)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('scenario_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='attack-replay-sandbox.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('attack_path_validation', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='replay_scenarios', to='enterprise.attackpathvalidation')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_attack_replay_scenarios', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_replay_scenarios', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_replay_scenarios', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', '-created_at'], name='idx_attack_replay_project'),
                    models.Index(fields=['attack_path_validation', '-created_at'], name='idx_attack_replay_validation'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_attack_replay_org_idem'),
                ],
            },
        ),
        migrations.CreateModel(
            name='AttackReplayRun',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('observed_controls', models.JSONField(default=list)),
                ('observation_evidence', models.JSONField(default=list)),
                ('result_snapshot', models.JSONField(default=dict)),
                ('outcome', models.CharField(choices=[('matched', 'Matched'), ('diverged', 'Diverged')], max_length=16)),
                ('input_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('result_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('comparison_sha256', models.CharField(editable=False, max_length=64)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='attack-replay-sandbox.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('executed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_replay_runs', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_replay_runs', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_replay_runs', to='projects.project')),
                ('scenario', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='runs', to='enterprise.attackreplayscenario')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'outcome', '-created_at'], name='idx_attack_replay_run_project'),
                    models.Index(fields=['scenario', '-created_at'], name='idx_attack_replay_run_scenario'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('scenario', 'idempotency_key'), name='uniq_attack_replay_run_idem'),
                ],
            },
        ),
    ]
