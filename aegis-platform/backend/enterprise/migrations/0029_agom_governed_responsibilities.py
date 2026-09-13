from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0028_assurance_recurrence_obligation_governance'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GovernedResponsibilityAssignment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('responsibility', models.CharField(choices=[('authorization_approver', 'Authorization Approver'), ('finding_confirmer', 'Finding Confirmer'), ('risk_approver', 'Risk Approver'), ('closure_approver', 'Closure Approver'), ('campaign_assessor', 'Campaign Assessor'), ('campaign_lead', 'Campaign Lead'), ('detection_publisher', 'Detection Publisher'), ('soc_closure_approver', 'SOC Closure Approver'), ('assurance_owner', 'Assurance Owner'), ('integration_acceptor', 'Integration Acceptor')], max_length=64)),
                ('scope_kind', models.CharField(choices=[('organization', 'Organization'), ('project', 'Project'), ('entity_type', 'Entity Type'), ('entity', 'Entity')], max_length=24)),
                ('entity_type', models.CharField(blank=True, max_length=80)),
                ('entity_id', models.CharField(blank=True, max_length=128)),
                ('valid_from', models.DateTimeField(default=django.utils.timezone.now)),
                ('valid_until', models.DateTimeField(blank=True, null=True)),
                ('reason', models.TextField()),
                ('policy_version', models.CharField(default='agom-responsibility.v1', max_length=64)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('grant_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('issued_at', models.DateTimeField(auto_now_add=True)),
                ('issued_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='issued_governed_responsibilities', to=settings.AUTH_USER_MODEL)),
                ('membership', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_assignments', to='enterprise.organizationmembership')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_assignments', to='enterprise.organization')),
                ('project', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_assignments', to='projects.project')),
                ('supersedes', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='superseded_by', to='enterprise.governedresponsibilityassignment')),
            ],
            options={'ordering': ['-issued_at', '-id']},
        ),
        migrations.CreateModel(
            name='GovernedResponsibilityRevocation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('reason', models.TextField()),
                ('policy_version', models.CharField(default='agom-responsibility.v1', max_length=64)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(db_index=True, editable=False, max_length=64)),
                ('revocation_fingerprint', models.CharField(editable=False, max_length=64, unique=True)),
                ('revoked_at', models.DateTimeField(auto_now_add=True)),
                ('assignment', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='revocation', to='enterprise.governedresponsibilityassignment')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_revocations', to='enterprise.organization')),
                ('revoked_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='revoked_governed_responsibilities', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-revoked_at', '-id']},
        ),
        migrations.CreateModel(
            name='GovernedResponsibilityEvent',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('event_type', models.CharField(choices=[('granted', 'Granted'), ('revoked', 'Revoked'), ('superseded', 'Superseded')], max_length=24)),
                ('payload', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, max_length=64)),
                ('entry_hash', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_events', to=settings.AUTH_USER_MODEL)),
                ('assignment', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governance_events', to='enterprise.governedresponsibilityassignment')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='governed_responsibility_events', to='enterprise.organization')),
            ],
            options={'ordering': ['id']},
        ),
        migrations.AddIndex(model_name='governedresponsibilityassignment', index=models.Index(fields=['organization', 'membership', 'responsibility'], name='idx_govresp_org_member')),
        migrations.AddIndex(model_name='governedresponsibilityassignment', index=models.Index(fields=['project', 'entity_type'], name='idx_govresp_project_entity')),
        migrations.AddIndex(model_name='governedresponsibilityassignment', index=models.Index(fields=['valid_until'], name='idx_govresp_valid_until')),
        migrations.AddIndex(model_name='governedresponsibilityrevocation', index=models.Index(fields=['organization', '-revoked_at'], name='idx_govresp_revoke_org')),
        migrations.AddIndex(model_name='governedresponsibilityevent', index=models.Index(fields=['organization', 'id'], name='idx_govresp_event_chain')),
        migrations.AddConstraint(model_name='governedresponsibilityassignment', constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govresp_grant_idem')),
        migrations.AddConstraint(model_name='governedresponsibilityrevocation', constraint=models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_govresp_revoke_idem')),
        migrations.AddConstraint(
            model_name='governedresponsibilityassignment',
            constraint=models.CheckConstraint(condition=models.Q(('valid_until__isnull', True), ('valid_until__gt', models.F('valid_from')), _connector='OR'), name='govresp_valid_window'),
        ),
        migrations.AddConstraint(
            model_name='governedresponsibilityassignment',
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(('entity_id', ''), ('entity_type', ''), ('project__isnull', True), ('scope_kind', 'organization'))
                    | models.Q(('entity_id', ''), ('entity_type', ''), ('project__isnull', False), ('scope_kind', 'project'))
                    | (models.Q(('entity_id', ''), ('project__isnull', False), ('scope_kind', 'entity_type')) & ~models.Q(('entity_type', '')))
                    | (models.Q(('project__isnull', False), ('scope_kind', 'entity')) & ~models.Q(('entity_type', '')) & ~models.Q(('entity_id', '')))
                ),
                name='govresp_scope_shape',
            ),
        ),
    ]
