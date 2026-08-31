from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0002_canonical_finding"),
    ]

    operations = [
        migrations.AddField(
            model_name="vulnerabilityevidence",
            name="collector_engine",
            field=models.CharField(blank=True, max_length=100, verbose_name="collector engine"),
        ),
    ]
