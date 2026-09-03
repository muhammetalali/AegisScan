import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0005_alter_technologyfingerprint_category_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='assetauthorization',
            name='correlation_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name='assetauthorization',
            name='expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='assetauthorization',
            name='supersedes',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='superseding_decisions',
                to='assets.assetauthorization',
            ),
        ),
        migrations.AddField(
            model_name='assetauthorization',
            name='valid_from',
            field=models.DateTimeField(auto_now_add=True),
        ),
        migrations.AlterModelOptions(
            name='assetauthorization',
            options={'ordering': ['-created_at', '-id']},
        ),
        migrations.RenameIndex(
            model_name='assetauthorization',
            old_name='assets_asse_asset_i_76122c_idx',
            new_name='assets_asse_asset_i_58150b_idx',
        ),
    ]
