from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0024_soc_closure_governance'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AssuranceConditionState',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('condition_key', models.CharField(max_length=64, unique=True)),
                ('state', models.CharField(choices=[('active', 'Active'), ('resolved', 'Resolved')], default='active', max_length=20)),
                ('generation', models.PositiveIntegerField(default=1)),
                ('version', models.PositiveIntegerField(default=1)),
                ('material_sha256', models.CharField(blank=True, max_length=64)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_condition_states', to='assets.asset')),
                ('finding', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_condition_state', to='vulnerabilities.vulnerability')),
                ('last_execution', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='condition_states', to='enterprise.continuousassuranceexecution')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_condition_states', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_condition_states', to='projects.project')),
            ],
            options={
                'indexes': [models.Index(fields=['project', 'state'], name='idx_assure_proj_state'), models.Index(fields=['asset', 'state'], name='idx_assure_asset_state')],
                'constraints': [models.UniqueConstraint(fields=('project', 'finding'), name='uniq_assurance_project_finding_state')],
            },
        ),
        migrations.CreateModel(
            name='AssuranceObservation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('classification', models.CharField(choices=[('new', 'New'), ('stable', 'Stable'), ('changed', 'Changed'), ('resolved', 'Resolved'), ('recurrent', 'Recurrent')], max_length=20)),
                ('generation', models.PositiveIntegerField()),
                ('state_version', models.PositiveIntegerField()),
                ('finding_present', models.BooleanField()),
                ('material_sha256', models.CharField(max_length=64)),
                ('payload_sha256', models.CharField(max_length=64)),
                ('replay_fingerprint', models.CharField(max_length=64, unique=True)),
                ('payload', models.JSONField(default=dict)),
                ('observed_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to='assets.asset')),
                ('evidence', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to='evidence.evidence')),
                ('execution', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_observations', to='enterprise.continuousassuranceexecution')),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to='vulnerabilities.vulnerability')),
                ('observed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to='enterprise.organization')),
                ('prior_closure', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='recurrence_observations', to='enterprise.investigationclosure')),
                ('prior_disposition', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='recurrence_observations', to='evidence.findingdisposition')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_observations', to='projects.project')),
            ],
            options={
                'ordering': ['observed_at', 'id'],
                'indexes': [models.Index(fields=['finding', '-observed_at'], name='idx_assure_find_time'), models.Index(fields=['project', 'classification'], name='idx_assure_proj_class')],
                'constraints': [models.UniqueConstraint(fields=('execution', 'finding'), name='uniq_assurance_exec_finding_obs')],
            },
        ),
    ]
