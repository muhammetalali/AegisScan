import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


def migrate_legacy_authorizations(apps, schema_editor):
    Asset = apps.get_model('assets', 'Asset')
    AssetAuthorization = apps.get_model('assets', 'AssetAuthorization')
    for asset in Asset.objects.filter(configuration__authorized=True, owner__isnull=False):
        configuration = asset.configuration or {}
        target = configuration.get('url') or configuration.get('host') or configuration.get('ip') or configuration.get('domain') or ''
        AssetAuthorization.objects.create(
            asset_id=asset.id,
            actor_id=asset.owner_id,
            authorized=True,
            target_snapshot=str(target)[:500],
            reason='Migrated from legacy persisted asset authorization flag',
        )


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AssetAuthorization',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('authorized', models.BooleanField(default=False)),
                ('target_snapshot', models.CharField(blank=True, max_length=500)),
                ('reason', models.CharField(blank=True, max_length=500)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='asset_authorization_actions', to=settings.AUTH_USER_MODEL)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='authorization_records', to='assets.asset')),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['asset', '-created_at'], name='assets_asse_asset_i_76122c_idx'),
                    models.Index(fields=['asset', 'authorized', '-created_at'], name='assets_asse_asset_i_ac3a40_idx'),
                ],
            },
        ),
        migrations.RunPython(migrate_legacy_authorizations, migrations.RunPython.noop),
    ]
