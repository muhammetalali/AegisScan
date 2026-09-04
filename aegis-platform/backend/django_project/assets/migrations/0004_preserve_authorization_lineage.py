import django.db.models.deletion
import uuid
from django.db import migrations, models


def backfill_asset_identity_snapshots(apps, schema_editor):
    AssetAuthorization = apps.get_model('assets', 'AssetAuthorization')
    for decision in AssetAuthorization.objects.select_related('asset').all():
        if decision.asset_id:
            decision.asset_identity_snapshot = decision.asset_id
            decision.save(update_fields=['asset_identity_snapshot'])


class Migration(migrations.Migration):
    dependencies = [('assets', '0003_assetauthorization')]
    operations = [
        migrations.AddField(model_name='assetauthorization', name='asset_identity_snapshot', field=models.UUIDField(default=uuid.uuid4, editable=False)),
        migrations.RunPython(backfill_asset_identity_snapshots, migrations.RunPython.noop),
        migrations.AlterField(model_name='assetauthorization', name='asset', field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='authorization_records', to='assets.asset')),
        migrations.AddIndex(model_name='assetauthorization', index=models.Index(fields=['asset_identity_snapshot', '-created_at'], name='assets_aa_identity_created_idx')),
    ]
