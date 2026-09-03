from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0007_authorization_request_identity'),
        ('scans', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='authorization_decision',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='bound_scans',
                to='assets.assetauthorization',
            ),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['authorization_decision'], name='scans_scan_authori_0bb523_idx'),
        ),
    ]
