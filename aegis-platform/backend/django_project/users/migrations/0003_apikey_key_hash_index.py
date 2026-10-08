"""Index hashed API-key digest for bounded, non-enumerable token lookup."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0002_rename_users_user_role_36d76_idx_users_user_role_36d76d_idx'),
    ]

    operations = [
        migrations.AlterField(
            model_name='apikey',
            name='key_hash',
            field=models.CharField('key hash', max_length=255, db_index=True),
        ),
    ]
