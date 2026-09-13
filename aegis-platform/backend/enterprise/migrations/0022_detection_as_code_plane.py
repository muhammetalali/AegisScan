import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('enterprise', '0021_cache_origin_security_validation_kind'),
        ('projects', '0002_initial'),
        ('vulnerabilities', '0002_delete_vulnerabilityevidence'),
        ('evidence', '0007_findingdisposition'),
    ]

    operations = [
        migrations.CreateModel(
            name='DetectionRule',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('slug', models.SlugField(max_length=180)),
                ('title', models.CharField(max_length=240)),
                ('description', models.TextField(blank=True)),
                ('state', models.CharField(choices=[('draft','Draft'),('validated','Validated'),('published','Published'),('retired','Retired')], default='draft', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_detection_rules', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_rules', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_rules', to='projects.project')),
            ],
            options={
                'indexes': [models.Index(fields=['project','state'], name='idx_detection_rule_project_state'), models.Index(fields=['organization','state'], name='idx_detection_rule_org_state')],
                'constraints': [models.UniqueConstraint(fields=('organization','project','slug'), name='uniq_detection_rule_scope_slug')],
            },
        ),
        migrations.CreateModel(
            name='DetectionRevision',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('version', models.PositiveIntegerField()),
                ('contract_version', models.CharField(default='aegis-detection.v1', max_length=32)),
                ('spec', models.JSONField()),
                ('content_sha256', models.CharField(max_length=64)),
                ('compiled', models.JSONField(default=dict)),
                ('attack_techniques', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_revisions', to=settings.AUTH_USER_MODEL)),
                ('rule', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='revisions', to='enterprise.detectionrule')),
                ('source_evidence', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='detection_revisions', to='evidence.evidence')),
                ('source_finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_revisions', to='vulnerabilities.vulnerability')),
            ],
            options={
                'ordering': ['rule_id','version'],
                'indexes': [models.Index(fields=['source_finding','-created_at'], name='idx_detection_revision_finding'), models.Index(fields=['content_sha256'], name='idx_detection_revision_sha')],
                'constraints': [models.UniqueConstraint(fields=('rule','version'), name='uniq_detection_rule_version'), models.UniqueConstraint(fields=('rule','content_sha256'), name='uniq_detection_rule_content')],
            },
        ),
        migrations.CreateModel(
            name='DetectionValidation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('telemetry_sha256', models.CharField(max_length=64)),
                ('telemetry_count', models.PositiveIntegerField()),
                ('matched_count', models.PositiveIntegerField()),
                ('minimum_matches', models.PositiveIntegerField(default=1)),
                ('status', models.CharField(choices=[('passed','Passed'),('failed','Failed')], max_length=20)),
                ('result_sha256', models.CharField(max_length=64)),
                ('result', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('revision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='validations', to='enterprise.detectionrevision')),
                ('tested_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_validations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['revision','status'], name='idx_detection_validation_state')],
                'constraints': [models.UniqueConstraint(fields=('revision','telemetry_sha256','minimum_matches'), name='uniq_detection_validation_input')],
            },
        ),
        migrations.CreateModel(
            name='DetectionPublication',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('package_sha256', models.CharField(max_length=64)),
                ('provider', models.CharField(max_length=30)),
                ('transport_status', models.PositiveIntegerField(blank=True, null=True)),
                ('response_sha256', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('integration', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publications', to='enterprise.externalintegration')),
                ('published_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publications', to=settings.AUTH_USER_MODEL)),
                ('revision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='publications', to='enterprise.detectionrevision')),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['integration','-created_at'], name='idx_detection_publication_integration')],
                'constraints': [models.UniqueConstraint(fields=('revision','integration','package_sha256'), name='uniq_detection_publication_package')],
            },
        ),
        migrations.CreateModel(
            name='DetectionEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=80)),
                ('payload', models.JSONField(default=dict)),
                ('entry_sha256', models.CharField(max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_events', to=settings.AUTH_USER_MODEL)),
                ('revision', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='events', to='enterprise.detectionrevision')),
                ('rule', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='events', to='enterprise.detectionrule')),
            ],
            options={
                'ordering': ['id'],
                'indexes': [models.Index(fields=['rule','created_at'], name='idx_detection_event_rule_time')],
            },
        ),
    ]
