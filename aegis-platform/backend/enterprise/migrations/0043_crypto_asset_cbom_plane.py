from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0042_provider_approval_plane'),
        ('assets', '0007_authorization_request_identity'),
        ('scans', '0004_governed_execution_contract'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CryptographicInventorySnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('snapshot_version', models.PositiveIntegerField()),
                ('source_type', models.CharField(max_length=64)),
                ('inventory_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('cbom', models.JSONField(default=dict)),
                ('cbom_sha256', models.CharField(db_index=True, editable=False, max_length=64)),
                ('risk_summary', models.JSONField(default=dict)),
                ('drift', models.JSONField(default=dict)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('policy_version', models.CharField(default='crypto-asset-cbom.v1', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to='assets.asset')),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to='assets.assetauthorization')),
                ('captured_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to='enterprise.organization')),
                ('predecessor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='successors', to='enterprise.cryptographicinventorysnapshot')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to='projects.project')),
                ('scan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='crypto_inventory_snapshots', to='scans.scan')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', '-snapshot_version'], name='idx_crypto_snapshot_latest'),
                    models.Index(fields=['organization', '-created_at'], name='idx_crypto_snapshot_org_time'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('project', 'asset', 'snapshot_version'), name='uniq_crypto_snapshot_asset_version'),
                ],
            },
        ),
        migrations.CreateModel(
            name='CryptographicAssetRecord',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ordinal', models.PositiveIntegerField()),
                ('kind', models.CharField(choices=[('certificate', 'Certificate'), ('key', 'Key'), ('protocol', 'Protocol'), ('algorithm', 'Algorithm'), ('library', 'Library')], max_length=24)),
                ('name', models.CharField(max_length=255)),
                ('algorithm', models.CharField(blank=True, max_length=128)),
                ('key_size', models.PositiveIntegerField(blank=True, null=True)),
                ('curve', models.CharField(blank=True, max_length=128)),
                ('protocol', models.CharField(blank=True, max_length=64)),
                ('version', models.CharField(blank=True, max_length=64)),
                ('issuer', models.CharField(blank=True, max_length=500)),
                ('subject', models.CharField(blank=True, max_length=500)),
                ('not_before', models.DateTimeField(blank=True, null=True)),
                ('not_after', models.DateTimeField(blank=True, null=True)),
                ('security_state', models.CharField(choices=[('acceptable', 'Acceptable'), ('weak', 'Weak'), ('deprecated', 'Deprecated'), ('expired', 'Expired'), ('unknown', 'Unknown')], max_length=20)),
                ('quantum_state', models.CharField(choices=[('vulnerable', 'Quantum Vulnerable'), ('resistant', 'Quantum Resistant'), ('hybrid', 'Hybrid'), ('unknown', 'Unknown')], max_length=20)),
                ('fingerprint_sha256', models.CharField(editable=False, max_length=64)),
                ('metadata', models.JSONField(default=dict)),
                ('snapshot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='records', to='enterprise.cryptographicinventorysnapshot')),
            ],
            options={
                'ordering': ['ordinal', 'id'],
                'indexes': [
                    models.Index(fields=['snapshot', 'kind'], name='idx_crypto_record_kind'),
                    models.Index(fields=['security_state'], name='idx_crypto_record_security'),
                    models.Index(fields=['quantum_state'], name='idx_crypto_record_quantum'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('snapshot', 'fingerprint_sha256'), name='uniq_crypto_record_snapshot_fingerprint'),
                    models.UniqueConstraint(fields=('snapshot', 'ordinal'), name='uniq_crypto_record_snapshot_ordinal'),
                ],
            },
        ),
    ]
