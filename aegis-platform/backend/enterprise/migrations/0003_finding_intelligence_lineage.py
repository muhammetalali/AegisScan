import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0002_initial'),
        ('intelligence', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='findingintelligence',
            name='analysis_version',
            field=models.CharField(default='1.0', max_length=20),
        ),
        migrations.AddField(
            model_name='findingintelligence',
            name='primary_cve',
            field=models.CharField(blank=True, db_index=True, max_length=32),
        ),
        migrations.AddField(
            model_name='findingintelligence',
            name='source_snapshot',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='finding_analyses',
                to='intelligence.intelligenceenrichment',
            ),
        ),
    ]
