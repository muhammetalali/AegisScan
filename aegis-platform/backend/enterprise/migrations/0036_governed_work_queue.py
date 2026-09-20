from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0035_detection_publication_delivery'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedWorkClaim',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('source_type', models.CharField(choices=[
                    ('governed_action_request', 'Governed Action Request'),
                    ('decision_action', 'Decision Action'),
                    ('assurance_obligation', 'Assurance Obligation'),
                    ('investigation_case', 'Investigation Case'),
                    ('detection_delivery', 'Detection Delivery'),
                ], max_length=40)),
                ('source_id', models.CharField(max_length=128)),
                ('claimed_at', models.DateTimeField(blank=True, null=True)),
                ('lease_expires_at', models.DateTimeField(blank=True, null=True)),
                ('version', models.PositiveIntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('claimed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claims', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claims', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claims', to='projects.project')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['project','source_type'], name='idx_gwork_project_type'),
                    models.Index(fields=['claimed_by','lease_expires_at'], name='idx_gwork_claim_lease'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('organization','source_type','source_id'), name='uniq_gwork_claim_source'),
                    models.CheckConstraint(
                        condition=(
                            models.Q(claimed_by__isnull=True, claimed_at__isnull=True, lease_expires_at__isnull=True)
                            | models.Q(claimed_by__isnull=False, claimed_at__isnull=False, lease_expires_at__isnull=False)
                        ),
                        name='gwork_claim_shape',
                    ),
                    models.CheckConstraint(condition=models.Q(version__gte=1), name='gwork_claim_version_gte_1'),
                ],
            },
        ),
        migrations.CreateModel(
            name='GovernedWorkClaimEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('sequence', models.PositiveIntegerField()),
                ('event_type', models.CharField(choices=[('claimed','Claimed'),('reclaimed','Reclaimed'),('renewed','Renewed'),('released','Released')], max_length=24)),
                ('idempotency_key', models.CharField(max_length=128)),
                ('request_fingerprint', models.CharField(max_length=64)),
                ('expected_version', models.PositiveIntegerField()),
                ('result_version', models.PositiveIntegerField()),
                ('lease_expires_at', models.DateTimeField(blank=True, null=True)),
                ('source_snapshot', models.JSONField(default=dict)),
                ('result_snapshot', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, max_length=64)),
                ('entry_hash', models.CharField(editable=False, max_length=64, unique=True)),
                ('occurred_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claim_events', to=settings.AUTH_USER_MODEL)),
                ('claim', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='events', to='enterprise.governedworkclaim')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claim_events', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claim_events', to='projects.project')),
                ('result_claimed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governed_work_claim_results', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['sequence','occurred_at','id'],
                'indexes': [
                    models.Index(fields=['project','occurred_at'], name='idx_gwork_event_project'),
                    models.Index(fields=['organization','event_type'], name='idx_gwork_event_type'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('claim','sequence'), name='uniq_gwork_event_sequence'),
                    models.UniqueConstraint(fields=('organization','idempotency_key'), name='uniq_gwork_org_idem'),
                    models.CheckConstraint(condition=models.Q(sequence__gte=1), name='gwork_event_sequence_gte_1'),
                    models.CheckConstraint(condition=models.Q(result_version=models.F('sequence')), name='gwork_event_result_sequence'),
                    models.CheckConstraint(condition=models.Q(result_version=models.F('expected_version') + 1), name='gwork_event_version_step'),
                    models.CheckConstraint(
                        condition=(
                            models.Q(result_claimed_by__isnull=True, lease_expires_at__isnull=True)
                            | models.Q(result_claimed_by__isnull=False, lease_expires_at__isnull=False)
                        ),
                        name='gwork_event_claim_shape',
                    ),
                ],
            },
        ),
    ]
