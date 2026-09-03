import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


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
                    models.Index(fields=['asset', '-created_at'], name='assets_asse_asset_id_4a6c1b_idx'),
                    models.Index(fields=['asset', 'authorized', '-created_at'], name='assets_asse_asset_id_7a4e6c_idx'),
                ],
            },
        ),
    ]
