from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('users', '0003_apikey_key_hash_index')]

    operations = [
        migrations.AddField(
            model_name='user',
            name='granted_permissions',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='enabled_scan_types',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='enabled_pages',
            field=models.JSONField(blank=True, default=None, null=True),
        ),
    ]
