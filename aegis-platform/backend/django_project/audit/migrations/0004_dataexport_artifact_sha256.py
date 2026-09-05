from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('audit', '0003_merge_0002')]

    operations = [
        migrations.AddField(
            model_name='dataexport',
            name='artifact_sha256',
            field=models.CharField(blank=True, max_length=64, verbose_name='artifact SHA-256'),
        ),
    ]
