from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('evidence', '0005_validationrun_authorization_decision'),
    ]

    operations = [
        migrations.CreateModel(
            name='FindingConfirmation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('verdict', models.CharField(choices=[('confirmed', 'Confirmed'), ('false_positive', 'False Positive')], max_length=20)),
                ('finding_present', models.BooleanField()),
                ('policy_version', models.CharField(default='finding-confirmation.v1', max_length=64)),
                ('evidence_sha256', models.CharField(max_length=64)),
                ('result_sha256', models.CharField(max_length=64)),
                ('request_fingerprint', models.CharField(max_length=64)),
                ('rationale', models.TextField(blank=True)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('authorization_decision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='finding_confirmations', to='assets.assetauthorization')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='finding_confirmations', to=settings.AUTH_USER_MODEL)),
                ('evidence', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='finding_confirmations', to='evidence.evidence')),
                ('finding', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='confirmation_records', to='vulnerabilities.vulnerability')),
                ('validation_run', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='finding_confirmation', to='evidence.validationrun')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddConstraint(
            model_name='findingconfirmation',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(('finding_present', True), ('verdict', 'confirmed')),
                    models.Q(('finding_present', False), ('verdict', 'false_positive')),
                    _connector='OR',
                ),
                name='evidence_confirmation_verdict_presence',
            ),
        ),
    ]
