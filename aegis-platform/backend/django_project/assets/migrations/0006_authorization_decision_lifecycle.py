import uuid

from django.db import migrations, models
import django.db.models.deletion


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
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='superseding_decisions', to='assets.assetauthorization'),
        ),
        migrations.AddField(
            model_name='assetauthorization',
            name='valid_from',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AlterModelOptions(
            name='assetauthorization',
            options={'ordering': ['-created_at', '-id']},
        ),
        migrations.AddIndex(
            model_name='assetauthorization',
            index=models.Index(fields=['asset', '-created_at', '-id'], name='assets_asse_asset_i_8c4e0e_idx'),
        ),
    ]
