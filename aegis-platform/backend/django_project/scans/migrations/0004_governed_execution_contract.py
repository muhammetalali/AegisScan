from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('scans', '0003_scan_authorization_decision')]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='execution_contract',
            field=models.JSONField(blank=True, default=dict, verbose_name='execution contract'),
        ),
        migrations.AddField(
            model_name='scan',
            name='execution_contract_fingerprint',
            field=models.CharField(blank=True, max_length=64, verbose_name='execution contract fingerprint'),
        ),
        migrations.AddField(
            model_name='scan',
            name='execution_correlation_id',
            field=models.CharField(blank=True, max_length=128, verbose_name='execution correlation ID'),
        ),
        migrations.AddField(
            model_name='scan',
            name='execution_idempotency_fingerprint',
            field=models.CharField(blank=True, max_length=64, verbose_name='execution idempotency fingerprint'),
        ),
        migrations.AddField(
            model_name='scan',
            name='execution_idempotency_key',
            field=models.CharField(blank=True, max_length=128, verbose_name='execution idempotency key'),
        ),
        migrations.AddConstraint(
            model_name='scan',
            constraint=models.UniqueConstraint(
                condition=~models.Q(execution_idempotency_key=''),
                fields=('project', 'initiated_by', 'execution_idempotency_key'),
                name='scans_scan_exec_idem_uq',
            ),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(
                fields=['project', 'execution_correlation_id'],
                name='scans_scan_proj_corr_idx',
            ),
        ),
    ]
