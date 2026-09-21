from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


def _install_iast_evidence_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute("""
        CREATE OR REPLACE FUNCTION aegis_iast_evidence_immutable()
        RETURNS trigger AS $
        BEGIN
            IF OLD.source = 'iast' OR (TG_OP = 'UPDATE' AND NEW.source = 'iast') THEN
                RAISE EXCEPTION 'IAST evidence is immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $ LANGUAGE plpgsql;
    """)
    schema_editor.execute("""
        DROP TRIGGER IF EXISTS trg_iast_evidence_immutable ON evidence_evidence;
        CREATE TRIGGER trg_iast_evidence_immutable
        BEFORE UPDATE OR DELETE ON evidence_evidence
        FOR EACH ROW EXECUTE FUNCTION aegis_iast_evidence_immutable();
    """)


def _remove_iast_evidence_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute('DROP TRIGGER IF EXISTS trg_iast_evidence_immutable ON evidence_evidence;')
    schema_editor.execute('DROP FUNCTION IF EXISTS aegis_iast_evidence_immutable();')


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0039_business_logic_assessment'),
        ('assets', '0007_authorization_request_identity'),
        ('scans', '0004_governed_execution_contract'),
        ('evidence', '0008_governed_oast_runtime'),
        ('vulnerabilities', '0003_vulnerability_governed_version'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='IASTSession',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('provider_identity', models.CharField(max_length=255)),
                ('provider_identity_sha256', models.CharField(editable=False, max_length=64)),
                ('instrumentation_mode', models.CharField(max_length=32)),
                ('target_snapshot', models.CharField(max_length=500)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='iast-enterprise.v1', max_length=64)),
                ('contract_snapshot', models.JSONField(default=dict)),
                ('contract_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_sessions', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_sessions', to='assets.assetauthorization')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_iast_sessions', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_sessions', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_sessions', to='projects.project')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_sessions', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', '-created_at'], name='idx_iast_session_project_asset'),
                    models.Index(fields=['authorization_decision', '-created_at'], name='idx_iast_session_authorization'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_iast_session_org_idem'),
                ],
            },
        ),
        migrations.CreateModel(
            name='IASTObservation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('observation_kind', models.CharField(max_length=64)),
                ('rule_id', models.CharField(max_length=200)),
                ('severity', models.CharField(max_length=16)),
                ('confidence', models.CharField(max_length=16)),
                ('source_kind', models.CharField(max_length=100)),
                ('sink_kind', models.CharField(max_length=100)),
                ('location', models.CharField(blank=True, max_length=500)),
                ('trace_id', models.CharField(max_length=128)),
                ('data_labels', models.JSONField(default=list)),
                ('metadata_snapshot', models.JSONField(default=dict)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('observation_sha256', models.CharField(editable=False, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('evidence', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='iast_observation', to='evidence.evidence')),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_observations', to='vulnerabilities.vulnerability')),
                ('observed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='iast_observations', to=settings.AUTH_USER_MODEL)),
                ('qualification', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='iast_observation', to='enterprise.evidencequalificationevaluation')),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='observations', to='enterprise.iastsession')),
            ],
            options={
                'ordering': ['created_at', 'id'],
                'indexes': [
                    models.Index(fields=['session', 'severity', 'created_at'], name='idx_iast_observation_session'),
                    models.Index(fields=['finding', 'created_at'], name='idx_iast_observation_finding'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('session', 'idempotency_key'), name='uniq_iast_observation_session_idem'),
                    models.UniqueConstraint(fields=('session', 'observation_sha256'), name='uniq_iast_observation_session_hash'),
                ],
            },
        ),
        migrations.RunPython(
            _install_iast_evidence_immutability,
            _remove_iast_evidence_immutability,
        ),
    ]
