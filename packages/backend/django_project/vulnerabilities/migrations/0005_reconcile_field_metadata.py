from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0004_backfill_evidence_collector_engine"),
    ]

    operations = [
        migrations.AlterField(
            model_name="vulnerability",
            name="first_seen",
            field=models.DateTimeField(auto_now_add=True),
        ),
        migrations.AlterField(
            model_name="vulnerability",
            name="fixed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="vulnerability",
            name="last_seen",
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="confidence",
            field=models.FloatField(default=0.5),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="corroboration_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="description",
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="location",
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="metadata",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="raw_data",
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="tags",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AlterField(
            model_name="vulnerabilityevidence",
            name="verified_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="vulnerabilitystatushistory",
            name="reason",
            field=models.TextField(blank=True),
        ),
    ]
