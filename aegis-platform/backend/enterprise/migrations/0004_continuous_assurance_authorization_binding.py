from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0007_authorization_request_identity'),
        ('enterprise', '0003_finding_intelligence_lineage'),
    ]
    operations = [
        migrations.AddField(
            model_name='continuousassuranceschedule', name='asset',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_schedules', to='assets.asset'),
        ),
        migrations.AddField(
            model_name='continuousassuranceschedule', name='authorization_decision',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_schedules', to='assets.assetauthorization'),
        ),
    ]
