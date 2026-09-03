from django.db import migrations, models


def backfill_valid_from(apps, schema_editor):
    AssetAuthorization = apps.get_model('assets', 'AssetAuthorization')
    AssetAuthorization.objects.filter(valid_from__isnull=True).update(valid_from=models.F('created_at'))


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0006_authorization_decision_lifecycle'),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name='assetauthorization',
            name='assets_asse_asset_i_76122c_idx',
        ),
        migrations.RenameIndex(
            model_name='assetauthorization',
            old_name='assets_asse_asset_i_8c4e0e_idx',
            new_name='assets_asse_asset_i_58150b_idx',
        ),
        migrations.RunPython(backfill_valid_from, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='assetauthorization',
            name='valid_from',
            field=models.DateTimeField(auto_now_add=True),
        ),
        migrations.AlterField(
            model_name='assetrelationship',
            name='metadata',
            field=models.JSONField(blank=True, default=dict, verbose_name='metadata'),
        ),
    ]
