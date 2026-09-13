from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0026_assurance_obligation_governance'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AdversaryCampaign',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=240)),
                ('status', models.CharField(choices=[('active', 'Active'), ('completed', 'Completed'), ('aborted', 'Aborted')], default='active', max_length=20)),
                ('scope_sha256', models.CharField(max_length=64)),
                ('version', models.PositiveIntegerField(default=1)),
                ('started_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('completion_sha256', models.CharField(blank=True, max_length=64)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_adversary_campaigns', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='adversary_campaigns', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='adversary_campaigns', to='projects.project')),
                ('source_asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='originating_adversary_campaigns', to='assets.asset')),
            ],
            options={'indexes': [models.Index(fields=['project', 'status'], name='idx_campaign_proj_state'), models.Index(fields=['source_asset', 'status'], name='idx_campaign_source_state')]},
        ),
        migrations.CreateModel(
            name='CampaignObjective',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=240)),
                ('objective_type', models.CharField(default='crown_jewel_access', max_length=80)),
                ('success_criteria', models.JSONField(default=dict)),
                ('attack_techniques', models.JSONField(default=list)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('reached', 'Reached'), ('blocked', 'Blocked'), ('inconclusive', 'Inconclusive')], default='pending', max_length=20)),
                ('generation', models.PositiveIntegerField(default=1)),
                ('version', models.PositiveIntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('campaign', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='objectives', to='enterprise.adversarycampaign')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_campaign_objectives', to=settings.AUTH_USER_MODEL)),
                ('target_asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='campaign_objectives', to='assets.asset')),
            ],
            options={
                'indexes': [models.Index(fields=['campaign', 'status'], name='idx_campaign_obj_state')],
                'constraints': [models.UniqueConstraint(fields=('campaign', 'target_asset'), name='uniq_campaign_target_objective')],
            },
        ),
        migrations.CreateModel(
            name='CampaignObjectiveAssessment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('outcome', models.CharField(choices=[('reached', 'Reached'), ('blocked', 'Blocked'), ('inconclusive', 'Inconclusive')], max_length=20)),
                ('reason_code', models.CharField(max_length=80)),
                ('explanation', models.TextField(blank=True)),
                ('path_risk_score', models.FloatField(default=0)),
                ('blast_radius_score', models.FloatField(default=0)),
                ('objective_generation', models.PositiveIntegerField()),
                ('objective_version', models.PositiveIntegerField()),
                ('proof_sha256', models.CharField(max_length=64)),
                ('replay_fingerprint', models.CharField(max_length=64, unique=True)),
                ('policy_version', models.CharField(default='campaign-objective.v1', max_length=64)),
                ('assessed_at', models.DateTimeField(auto_now_add=True)),
                ('assessed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='campaign_objective_assessments', to=settings.AUTH_USER_MODEL)),
                ('attack_path', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='objective_assessments', to='enterprise.attackpath')),
                ('blast_radius_snapshot', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='objective_assessments', to='enterprise.blastradiussnapshot')),
                ('evidence', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='campaign_objective_assessments', to='evidence.evidence')),
                ('objective', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assessments', to='enterprise.campaignobjective')),
                ('validation_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='campaign_objective_assessments', to='evidence.validationrun')),
            ],
            options={'ordering': ['assessed_at', 'id'], 'indexes': [models.Index(fields=['objective', '-assessed_at'], name='idx_campaign_obj_assess'), models.Index(fields=['outcome', '-assessed_at'], name='idx_campaign_outcome_time')]},
        ),
        migrations.CreateModel(
            name='CampaignAuditEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=80)),
                ('payload', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, max_length=64)),
                ('entry_hash', models.CharField(max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='campaign_audit_events', to=settings.AUTH_USER_MODEL)),
                ('campaign', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='audit_events', to='enterprise.adversarycampaign')),
            ],
            options={'ordering': ['id'], 'indexes': [models.Index(fields=['campaign', 'id'], name='idx_campaign_audit_event')]},
        ),
    ]
