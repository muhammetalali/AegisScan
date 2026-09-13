from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0025_assurance_drift_recurrence_governance'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AssuranceObligation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('kind', models.CharField(choices=[('disposition_review', 'Disposition Review')], default='disposition_review', max_length=32)),
                ('status', models.CharField(choices=[('open', 'Open'), ('due', 'Due'), ('overdue', 'Overdue'), ('satisfied', 'Satisfied'), ('superseded', 'Superseded')], default='open', max_length=20)),
                ('due_at', models.DateTimeField()),
                ('generation', models.PositiveIntegerField(default=1)),
                ('version', models.PositiveIntegerField(default=1)),
                ('satisfied_at', models.DateTimeField(blank=True, null=True)),
                ('superseded_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='assets.asset')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='created_assurance_obligations', to=settings.AUTH_USER_MODEL)),
                ('disposition', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation', to='evidence.findingdisposition')),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='vulnerabilities.vulnerability')),
                ('last_execution', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governance_obligations', to='enterprise.continuousassuranceexecution')),
                ('last_observation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governance_obligations', to='enterprise.assuranceobservation')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='projects.project')),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governance_obligations', to='enterprise.continuousassuranceschedule')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['project', 'status', 'due_at'], name='idx_aobl_proj_status_due'),
                    models.Index(fields=['finding', 'status'], name='idx_aobl_find_status'),
                ],
                'constraints': [
                    models.CheckConstraint(
                        condition=(
                            models.Q(('satisfied_at__isnull', False), ('status', 'satisfied'), ('superseded_at__isnull', True))
                            | models.Q(('satisfied_at__isnull', True), ('status', 'superseded'), ('superseded_at__isnull', False))
                            | models.Q(('satisfied_at__isnull', True), ('status__in', ['open', 'due', 'overdue']), ('superseded_at__isnull', True))
                        ),
                        name='assurance_obligation_terminal_shape',
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name='AssuranceObligationEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('sequence', models.PositiveIntegerField()),
                ('event_type', models.CharField(choices=[('created', 'Created'), ('due', 'Due'), ('overdue', 'Overdue'), ('satisfied', 'Satisfied'), ('superseded', 'Superseded'), ('revalidated_present', 'Revalidated Present')], max_length=32)),
                ('payload', models.JSONField(default=dict)),
                ('payload_sha256', models.CharField(max_length=64)),
                ('replay_fingerprint', models.CharField(max_length=64, unique=True)),
                ('occurred_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation_events', to=settings.AUTH_USER_MODEL)),
                ('disposition', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation_events', to='evidence.findingdisposition')),
                ('execution', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governance_events', to='enterprise.continuousassuranceexecution')),
                ('obligation', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='events', to='enterprise.assuranceobligation')),
                ('observation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='obligation_events', to='enterprise.assuranceobservation')),
                ('risk_correlation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation_events', to='enterprise.riskcorrelationsnapshot')),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governance_events', to='enterprise.continuousassuranceschedule')),
            ],
            options={
                'ordering': ['sequence', 'occurred_at', 'id'],
                'indexes': [
                    models.Index(fields=['obligation', 'event_type'], name='idx_aobl_event_type'),
                    models.Index(fields=['occurred_at'], name='idx_aobl_event_time'),
                ],
                'constraints': [models.UniqueConstraint(fields=('obligation', 'sequence'), name='uniq_aobl_event_sequence')],
            },
        ),
    ]
