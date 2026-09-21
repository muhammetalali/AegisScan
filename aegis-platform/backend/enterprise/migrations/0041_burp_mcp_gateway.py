from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


def _install_burp_mcp_evidence_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute("""
        CREATE OR REPLACE FUNCTION aegis_burp_mcp_evidence_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS '
        BEGIN
            IF OLD.source = ''burp_mcp'' THEN
                RAISE EXCEPTION ''Burp MCP evidence is immutable'';
            END IF;
            IF TG_OP = ''UPDATE'' AND NEW.source = ''burp_mcp'' THEN
                RAISE EXCEPTION ''Burp MCP evidence is immutable'';
            END IF;
            IF TG_OP = ''DELETE'' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        ';
    """)
    schema_editor.execute("""
        DROP TRIGGER IF EXISTS trg_burp_mcp_evidence_immutable ON evidence_evidence;
        CREATE TRIGGER trg_burp_mcp_evidence_immutable
        BEFORE UPDATE OR DELETE ON evidence_evidence
        FOR EACH ROW EXECUTE FUNCTION aegis_burp_mcp_evidence_immutable();
    """)


def _remove_burp_mcp_evidence_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute('DROP TRIGGER IF EXISTS trg_burp_mcp_evidence_immutable ON evidence_evidence;')
    schema_editor.execute('DROP FUNCTION IF EXISTS aegis_burp_mcp_evidence_immutable();')


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0040_iast_enterprise_security_plane'),
        ('assets', '0007_authorization_request_identity'),
        ('scans', '0004_governed_execution_contract'),
        ('evidence', '0008_governed_oast_runtime'),
        ('system', '0004_alter_credentialsecret_kind'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BurpMCPSession',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('provider_name', models.CharField(max_length=180)),
                ('provider_version', models.CharField(max_length=120)),
                ('provider_identity_sha256', models.CharField(editable=False, max_length=64)),
                ('endpoint_origin', models.CharField(max_length=500)),
                ('target_snapshot', models.CharField(max_length=500)),
                ('allowed_tools', models.JSONField(default=list)),
                ('max_invocations', models.PositiveSmallIntegerField(default=20)),
                ('rate_limit_per_minute', models.PositiveSmallIntegerField(default=10)),
                ('expires_at', models.DateTimeField()),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='burp-mcp-gateway.v1', max_length=64)),
                ('contract_snapshot', models.JSONField(default=dict)),
                ('contract_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='assets.assetauthorization')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_burp_mcp_sessions', to=settings.AUTH_USER_MODEL)),
                ('credential_ref', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='system.credentialsecret')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='projects.project')),
                ('provider_approval', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='enterprise.providerapprovalrecord')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_sessions', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', '-created_at'], name='idx_burp_mcp_project_asset'),
                    models.Index(fields=['provider_approval', '-created_at'], name='idx_burp_mcp_approval'),
                    models.Index(fields=['expires_at'], name='idx_burp_mcp_expiry'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_burp_mcp_org_idem'),
                ],
            },
        ),
        migrations.CreateModel(
            name='BurpMCPInvocation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('operation', models.CharField(max_length=80)),
                ('provider_tool_name', models.CharField(max_length=180)),
                ('invocation_sequence', models.PositiveIntegerField()),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('arguments_sha256', models.CharField(editable=False, max_length=64)),
                ('provider_result_sha256', models.CharField(editable=False, max_length=64)),
                ('evidence_sha256', models.CharField(editable=False, max_length=64)),
                ('provider_request_id', models.CharField(blank=True, max_length=128)),
                ('result_summary', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('evidence', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_invocation', to='evidence.evidence')),
                ('invoked_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_invocations', to=settings.AUTH_USER_MODEL)),
                ('qualification', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='burp_mcp_invocation', to='enterprise.evidencequalificationevaluation')),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='invocations', to='enterprise.burpmcpsession')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'indexes': [
                    models.Index(fields=['session', 'created_at'], name='idx_burp_mcp_session_time'),
                    models.Index(fields=['operation', 'created_at'], name='idx_burp_mcp_operation'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('session', 'idempotency_key'), name='uniq_burp_mcp_invocation_idem'),
                    models.UniqueConstraint(fields=('session', 'invocation_sequence'), name='uniq_burp_mcp_invocation_seq'),
                ],
            },
        ),
        migrations.RunPython(
            _install_burp_mcp_evidence_immutability,
            _remove_burp_mcp_evidence_immutability,
        ),
    ]
