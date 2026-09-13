from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0027_adversary_campaign_objective_assurance'),
    ]

    operations = [
        migrations.AlterField(
            model_name='assuranceobligation',
            name='disposition',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation', to='evidence.findingdisposition'),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='source_disposition',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='recurrence_assurance_obligations', to='evidence.findingdisposition'),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='source_observation',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='recurrence_obligation', to='enterprise.assuranceobservation'),
        ),
        migrations.AlterField(
            model_name='assuranceobligation',
            name='kind',
            field=models.CharField(choices=[('disposition_review', 'Disposition Review'), ('recurrence_review', 'Recurrence Review')], default='disposition_review', max_length=32),
        ),
        migrations.AlterField(
            model_name='assuranceobligationevent',
            name='disposition',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation_events', to='evidence.findingdisposition'),
        ),
        migrations.AddConstraint(
            model_name='assuranceobligation',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(('disposition__isnull', False), ('kind', 'disposition_review'), ('source_observation__isnull', True))
                    | models.Q(('disposition__isnull', True), ('kind', 'recurrence_review'), ('source_observation__isnull', False))
                ),
                name='assurance_obligation_source_shape',
            ),
        ),
    ]