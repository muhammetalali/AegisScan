import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0008_decision_action_model_state'),
        ('evidence', '0005_validationrun_authorization_decision'),
        ('projects', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='decisionaction',
            name='organization',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='decision_actions',
                to='enterprise.organization',
            ),
        ),
        migrations.AddField(
            model_name='decisionaction',
            name='project',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='decision_actions',
                to='projects.project',
            ),
        ),
        migrations.AddField(
            model_name='decisionaction',
            name='validation',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='decision_actions',
                to='evidence.validationrun',
            ),
        ),
        migrations.AddIndex(
            model_name='decisionaction',
            index=models.Index(fields=['organization', 'state'], name='idx_actions_org_state'),
        ),
        migrations.AddIndex(
            model_name='decisionaction',
            index=models.Index(fields=['project', 'state'], name='idx_actions_project_state'),
        ),
    ]
