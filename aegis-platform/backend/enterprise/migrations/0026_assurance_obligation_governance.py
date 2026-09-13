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
                ('source_type', models.CharField(choices=[('risk_review', 'Risk Review'), ('recurrence', 'Recurrence')], max_length=20)),
                ('source_sha256', models.CharField(max_length=64)),
                ('source_fingerprint', models.CharField(max_length=64, unique=True)),
                ('policy_id', models.CharField(max_length=120)),
                ('policy_version', models.PositiveIntegerField(default=1)),
                ('sla_hours', models.PositiveIntegerField()),
                ('due_at', models.DateTimeField()),
                ('status', models.CharField(choices=[('open', 'Open'), ('satisfied', 'Satisfied'), ('superseded', 'Superseded')], default='open', max_length=20)),
                ('sla_status', models.CharField(choices=[('on_track', 'On Track'), ('at_risk', 'At Risk'), ('breached', 'Breached')], default='on_track', max_length=20)),
                ('escalation_level', models.PositiveIntegerField(default=0)),
                ('generation', models.PositiveIntegerField(default=1)),
                ('version', models.PositiveIntegerField(default=1)),
                ('satisfied_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='vulnerabilities.vulnerability')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='enterprise.organization')),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='owned_assurance_obligations', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='projects.project')),
                ('satisfied_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='satisfied_assurance_obligations', to=settings.AUTH_USER_MODEL)),
                ('satisfied_observation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='satisfied_obligations', to='enterprise.assuranceobservation')),
                ('source_disposition', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligations', to='evidence.findingdisposition')),
                ('source_observation', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation', to='enterprise.assuranceobservation')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['project', 'status', 'due_at'], name='idx_assure_obl_proj_due'),
                    models.Index(fields=['finding', 'status'], name='idx_assure_obl_find_state'),
                    models.Index(fields=['sla_status', 'due_at'], name='idx_assure_obl_sla_due'),
                ],
                'constraints': [
                    models.CheckConstraint(condition=(models.Q(source_type='risk_review', source_disposition__isnull=False, source_observation__isnull=True) | models.Q(source_type='recurrence', source_observation__isnull=False)), name='assure_obligation_source_shape'),
                    models.CheckConstraint(condition=(models.Q(status='satisfied', satisfied_observation__isnull=False, satisfied_by__isnull=False, satisfied_at__isnull=False) | models.Q(status__in=['open', 'superseded'], satisfied_observation__isnull=True, satisfied_by__isnull=True, satisfied_at__isnull=True)), name='assure_obligation_satisfaction_shape'),
                ],
            },
        ),
        migrations.CreateModel(
            name='AssuranceObligationEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(max_length=80)),
                ('payload', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, max_length=64)),
                ('entry_hash', models.CharField(max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='assurance_obligation_events', to=settings.AUTH_USER_MODEL)),
                ('obligation', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='events', to='enterprise.assuranceobligation')),
            ],
            options={
                'ordering': ['id'],
                'indexes': [models.Index(fields=['obligation', 'id'], name='idx_assure_obl_event')],
            },
        ),
    ]
