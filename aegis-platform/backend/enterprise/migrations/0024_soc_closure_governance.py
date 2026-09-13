import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('enterprise', '0023_security_operations_plane'),
        ('evidence', '0008_finding_disposition'),
        ('vulnerabilities', '0002_delete_vulnerabilityevidence'),
    ]

    operations = [
        migrations.CreateModel(
            name='InvestigationClosure',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('closure_type', models.CharField(choices=[('remediated', 'Remediated'), ('accepted_risk', 'Accepted Risk'), ('wont_fix', "Won't Fix"), ('duplicate', 'Duplicate')], max_length=20)),
                ('policy_version', models.CharField(default='soc-closure.v1', max_length=64)),
                ('source_sha256', models.CharField(max_length=64)),
                ('closure_fingerprint', models.CharField(max_length=64, unique=True)),
                ('rationale', models.TextField(blank=True)),
                ('closed_at', models.DateTimeField(auto_now_add=True)),
                ('case', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='governed_closure', to='enterprise.investigationcase')),
                ('closed_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='investigation_closures', to=settings.AUTH_USER_MODEL)),
                ('decision_action', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='closure_records', to='enterprise.decisionaction')),
                ('disposition', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='investigation_closures', to='evidence.findingdisposition')),
                ('evidence', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='investigation_closures', to='evidence.evidence')),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='investigation_closures', to='vulnerabilities.vulnerability')),
                ('validation_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='investigation_closures', to='evidence.validationrun')),
            ],
            options={
                'indexes': [models.Index(fields=['finding', '-closed_at'], name='idx_soc_closure_finding'), models.Index(fields=['closure_type', '-closed_at'], name='idx_soc_closure_type')],
                'constraints': [models.CheckConstraint(condition=(models.Q(('closure_type', 'remediated'), ('disposition__isnull', True), ('evidence__isnull', False), ('validation_run__isnull', False)) | models.Q(('closure_type__in', ['accepted_risk', 'wont_fix', 'duplicate']), ('disposition__isnull', False), ('validation_run__isnull', True))), name='soc_closure_lineage_shape')],
            },
        ),
    ]
