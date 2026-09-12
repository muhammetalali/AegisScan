from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0007_authorization_request_identity'),
        ('evidence', '0004_rename_evidence_va_finding_4a83d4_idx_evidence_va_finding_25b851_idx'),
    ]
    operations = [
        migrations.AddField(
            model_name='validationrun',
            name='authorization_decision',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='bound_validations', to='assets.assetauthorization'),
        ),
        migrations.AddIndex(
            model_name='validationrun',
            index=models.Index(fields=['authorization_decision'], name='evidence_v_authori_5f0c72_idx'),
        ),
    ]
