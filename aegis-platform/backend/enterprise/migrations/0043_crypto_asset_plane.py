from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0042_provider_approval_plane'),
        ('assets', '0007_authorization_request_identity'),
        ('projects', '0003_governed_scheduled_scan'),
        ('scans', '0004_governed_execution_contract'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CryptographicInventorySnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('source_kind', models.CharField(max_length=64)),
                ('source_ref', models.CharField(blank=True, max_length=255)),
                ('source_evidence_refs', models.JSONField(default=list)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('inventory_version', models.PositiveIntegerField()),
                ('component_count', models.PositiveIntegerField(default=0)),
                ('inventory_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('drift_summary', models.JSONField(default=dict)),
                ('drift_sha256', models.CharField(editable=False, max_length=64)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='crypto-asset-plane.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='cryptographic_inventory_snapshots', to='assets.asset')),
                ('collected_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='cryptographic_inventory_snapshots', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='cryptographic_inventory_snapshots', to='enterprise.organization')),
                ('predecessor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='successors', to='enterprise.cryptographicinventorysnapshot')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='cryptographic_inventory_snapshots', to='projects.project')),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='cryptographic_inventory_snapshots', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', '-inventory_version'], name='idx_crypto_inventory_latest'),
                    models.Index(fields=['organization', '-created_at'], name='idx_crypto_inventory_org_time'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('asset', 'inventory_version'), name='uniq_crypto_inventory_asset_version'),
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_crypto_inventory_org_idem'),
                ],
            },
        ),
        migrations.CreateModel(
            name='CryptographicAssetRecord',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('component_ref', models.CharField(max_length=160)),
                ('asset_type', models.CharField(choices=[('algorithm', 'Algorithm'), ('certificate', 'Certificate'), ('protocol', 'Protocol'), ('related-crypto-material', 'Related Cryptographic Material')], max_length=32)),
                ('name', models.CharField(max_length=255)),
                ('location', models.CharField(blank=True, max_length=500)),
                ('owner_ref', models.CharField(blank=True, max_length=255)),
                ('algorithm_family', models.CharField(blank=True, max_length=100)),
                ('primitive', models.CharField(blank=True, max_length=64)),
                ('parameter_set', models.CharField(blank=True, max_length=120)),
                ('key_size', models.PositiveIntegerField(blank=True, null=True)),
                ('curve', models.CharField(blank=True, max_length=120)),
                ('protocol_type', models.CharField(blank=True, max_length=64)),
                ('protocol_version', models.CharField(blank=True, max_length=64)),
                ('material_type', models.CharField(blank=True, max_length=64)),
                ('material_state', models.CharField(blank=True, max_length=64)),
                ('protection_mechanism', models.CharField(blank=True, max_length=120)),
                ('fingerprint_sha256', models.CharField(blank=True, max_length=64)),
                ('certificate_subject', models.CharField(blank=True, max_length=500)),
                ('certificate_issuer', models.CharField(blank=True, max_length=500)),
                ('certificate_serial', models.CharField(blank=True, max_length=255)),
                ('not_valid_before', models.DateTimeField(blank=True, null=True)),
                ('not_valid_after', models.DateTimeField(blank=True, null=True)),
                ('nist_quantum_security_level', models.PositiveSmallIntegerField(blank=True, null=True)),
                ('relationships', models.JSONField(default=list)),
                ('metadata_snapshot', models.JSONField(default=dict)),
                ('component_sha256', models.CharField(editable=False, max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('snapshot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='components', to='enterprise.cryptographicinventorysnapshot')),
            ],
            options={
                'ordering': ['component_ref'],
                'indexes': [
                    models.Index(fields=['snapshot', 'asset_type'], name='idx_crypto_component_kind'),
                    models.Index(fields=['algorithm_family'], name='idx_crypto_component_algorithm'),
                    models.Index(fields=['not_valid_after'], name='idx_crypto_component_expiry'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('snapshot', 'component_ref'), name='uniq_crypto_component_snapshot_ref'),
                ],
            },
        ),
        migrations.CreateModel(
            name='CBOMArtifact',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('format', models.CharField(default='cyclonedx-json', max_length=32)),
                ('spec_version', models.CharField(default='1.7', max_length=16)),
                ('serial_number', models.CharField(max_length=128, unique=True)),
                ('document', models.JSONField(default=dict)),
                ('document_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('generated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='generated_cbom_artifacts', to=settings.AUTH_USER_MODEL)),
                ('snapshot', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='cbom', to='enterprise.cryptographicinventorysnapshot')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [models.Index(fields=['snapshot', 'spec_version'], name='idx_cbom_snapshot_spec')],
            },
        ),
    ]
