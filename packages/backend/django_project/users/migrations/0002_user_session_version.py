from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='session_version',
            field=models.PositiveBigIntegerField(default=1, editable=False, verbose_name='session version'),
        ),
    ]
