from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0007_authorization_request_identity'),
        ('evidence', '0002_initial'),
        ('vulnerabilities', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='validationrun',
            name='finding',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='validation_runs',
                to='vulnerabilities.vulnerability',
            ),
        ),
        migrations.AddField(
            model_name='validationrun',
            name='finding_identity_snapshot',
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name='validationrun',
            name='authorization_decision',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='validation_runs',
                to='assets.assetauthorization',
            ),
        ),
        migrations.AddIndex(
            model_name='validationrun',
            index=models.Index(fields=['finding', 'created_at'], name='evidence_val_finding_created_idx'),
        ),
        migrations.AddIndex(
            model_name='validationrun',
            index=models.Index(fields=['authorization_decision'], name='evidence_val_auth_decision_idx'),
        ),
    ]
