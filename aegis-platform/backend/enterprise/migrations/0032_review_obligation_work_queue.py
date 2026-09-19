from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0031_agom_evidence_qualification'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='assuranceobligation',
            name='assigned_to',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assigned_assurance_obligations', to='enterprise.organizationmembership'),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='assigned_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assigned_assurance_obligations', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='assigned_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='acknowledged_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='acknowledged_assurance_obligations', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='acknowledged_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='priority',
            field=models.CharField(choices=[('p0_critical', 'P0 Critical'), ('p1_high', 'P1 High'), ('p2_medium', 'P2 Medium'), ('p3_low', 'P3 Low')], default='p2_medium', max_length=24),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='sla_status',
            field=models.CharField(choices=[('on_track', 'On Track'), ('at_risk', 'At Risk'), ('breached', 'Breached'), ('closed', 'Closed')], default='on_track', max_length=20),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='escalation_level',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='escalation_targets',
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='last_escalated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='policy_id',
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name='assuranceobligation',
            name='policy_version',
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AlterField(
            model_name='assuranceobligationevent',
            name='event_type',
            field=models.CharField(choices=[('created', 'Created'), ('due', 'Due'), ('overdue', 'Overdue'), ('satisfied', 'Satisfied'), ('superseded', 'Superseded'), ('revalidated_present', 'Revalidated Present'), ('assigned', 'Assigned'), ('acknowledged', 'Acknowledged'), ('sla_at_risk', 'SLA At Risk'), ('sla_breached', 'SLA Breached'), ('sla_closed', 'SLA Closed')], max_length=32),
        ),
        migrations.AddIndex(
            model_name='assuranceobligation',
            index=models.Index(fields=['project', 'priority', 'due_at'], name='idx_aobl_proj_prio_due'),
        ),
        migrations.AddIndex(
            model_name='assuranceobligation',
            index=models.Index(fields=['assigned_to', 'sla_status', 'due_at'], name='idx_aobl_assignee_sla'),
        ),
        migrations.AddConstraint(
            model_name='assuranceobligation',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(assigned_to__isnull=True, assigned_by__isnull=True, assigned_at__isnull=True)
                    | models.Q(assigned_to__isnull=False, assigned_by__isnull=False, assigned_at__isnull=False)
                ),
                name='assurance_obligation_assignment_shape',
            ),
        ),
        migrations.AddConstraint(
            model_name='assuranceobligation',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(acknowledged_by__isnull=True, acknowledged_at__isnull=True)
                    | models.Q(acknowledged_by__isnull=False, acknowledged_at__isnull=False)
                ),
                name='assurance_obligation_ack_shape',
            ),
        ),
    ]
