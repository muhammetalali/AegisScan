from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0041_burp_mcp_gateway'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ProviderApprovalDecision',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('provider_name', models.CharField(max_length=180)),
                ('provider_version', models.CharField(max_length=120)),
                ('capability', models.CharField(max_length=180)),
                ('provider_identity_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('status', models.CharField(choices=[('approved', 'Approved'), ('experimental', 'Experimental'), ('restricted', 'Restricted'), ('revoked', 'Revoked'), ('rejected', 'Rejected')], max_length=20)),
                ('trust_state', models.CharField(choices=[('trusted', 'Trusted'), ('conditional', 'Conditional'), ('untrusted', 'Untrusted')], max_length=20)),
                ('decision_version', models.PositiveIntegerField()),
                ('manifest', models.JSONField(default=dict)),
                ('manifest_sha256', models.CharField(editable=False, max_length=64)),
                ('capability_manifest', models.JSONField(default=dict)),
                ('capability_manifest_sha256', models.CharField(editable=False, max_length=64)),
                ('supply_chain_evidence', models.JSONField(default=dict)),
                ('supply_chain_sha256', models.CharField(editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='provider-approval-enterprise.v1', max_length=64)),
                ('rationale', models.TextField(blank=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('legacy_approval', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='enterprise_decisions', to='enterprise.providerapprovalrecord')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='provider_approval_decisions', to='enterprise.organization')),
                ('predecessor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='successors', to='enterprise.providerapprovaldecision')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='enterprise_provider_approval_decisions', to='projects.project')),
                ('reviewed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='enterprise_provider_approval_decisions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'provider_name', 'capability', '-decision_version'], name='idx_provider_decision_latest'),
                    models.Index(fields=['organization', 'status', 'trust_state'], name='idx_provider_decision_trust'),
                    models.Index(fields=['provider_name', 'provider_version', 'capability'], name='idx_provider_decision_identity'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('project', 'provider_name', 'capability', 'decision_version'), name='uniq_provider_decision_lineage_version'),
                ],
            },
        ),
        migrations.AddField(
            model_name='burpmcpsession',
            name='provider_governance_decision',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='burp_mcp_sessions',
                to='enterprise.providerapprovaldecision',
            ),
        ),
    ]
