import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0014_risk_correlation_snapshot'),
    ]

    operations = [
        migrations.AddField(
            model_name='decisionaction',
            name='risk_correlation',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='decision_actions',
                to='enterprise.riskcorrelationsnapshot',
            ),
        ),
        migrations.AddIndex(
            model_name='decisionaction',
            index=models.Index(
                fields=['risk_correlation', 'state'],
                name='idx_actions_riskcorr_state',
            ),
        ),
    ]
