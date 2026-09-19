# Generated for governed OAST runtime persistence.

import uuid
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('evidence', '0007_findingdisposition'),
        ('assets', '0007_authorization_request_identity'),
        ('projects', '0002_initial'),
        ('scans', '0004_governed_execution_contract'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedOASTSession',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('target_snapshot', models.CharField(max_length=500)),
                ('execution_id', models.CharField(max_length=128)),
                ('request_fingerprint', models.CharField(max_length=64, unique=True)),
                ('token_sha256', models.CharField(max_length=64)),
                ('expires_at', models.DateTimeField()),
                ('max_interactions', models.PositiveSmallIntegerField(default=8)),
                ('policy_version', models.CharField(default='governed-oast.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='oast_sessions', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='oast_sessions', to='assets.assetauthorization')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_oast_sessions', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='oast_sessions', to='projects.project')),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='oast_sessions', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['project', '-created_at'], name='idx_oast_session_project'),
                    models.Index(fields=['asset', '-created_at'], name='idx_oast_session_asset'),
                    models.Index(fields=['execution_id'], name='idx_oast_session_execution'),
                    models.Index(fields=['expires_at'], name='idx_oast_session_expiry'),
                ],
                'constraints': [
                    models.CheckConstraint(
                        condition=models.Q(('max_interactions__gte', 1), ('max_interactions__lte', 64)),
                        name='evidence_oast_max_interactions',
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name='GovernedOASTInteraction',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('protocol', models.CharField(choices=[('http', 'HTTP'), ('dns', 'DNS')], max_length=8)),
                ('fingerprint', models.CharField(max_length=64)),
                ('source_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('request_method', models.CharField(blank=True, max_length=16)),
                ('payload_sha256', models.CharField(blank=True, max_length=64)),
                ('payload_size', models.PositiveIntegerField(default=0)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('observed_at', models.DateTimeField(auto_now_add=True)),
                ('evidence', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='oast_interaction', to='evidence.evidence')),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='interactions', to='evidence.governedoastsession')),
            ],
            options={
                'ordering': ['observed_at', 'id'],
                'indexes': [
                    models.Index(fields=['session', 'protocol', 'observed_at'], name='idx_oast_interaction_session'),
                    models.Index(fields=['fingerprint'], name='idx_oast_interaction_fp'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('session', 'fingerprint'), name='evidence_oast_session_fingerprint_uq'),
                ],
            },
        ),
    ]
