from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('audit', '0001_initial')]

    operations = [
        migrations.AddField(
            model_name='auditlog',
            name='sequence',
            field=models.PositiveBigIntegerField(editable=False, null=True, unique=True, verbose_name='chain sequence'),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='previous_hash',
            field=models.CharField(blank=True, editable=False, max_length=64, verbose_name='previous hash'),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(blank=True, editable=False, max_length=64, verbose_name='entry hash'),
        ),
        migrations.AddIndex(
            model_name='auditlog',
            index=models.Index(fields=['sequence'], name='audit_audit_sequence_idx'),
        ),
    ]
