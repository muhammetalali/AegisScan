from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0004_preserve_authorization_lineage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='technologyfingerprint',
            name='category',
            field=models.CharField(max_length=50, verbose_name='category'),
        ),
        migrations.AlterField(
            model_name='technologyfingerprint',
            name='source',
            field=models.CharField(max_length=50, verbose_name='source'),
        ),
    ]
