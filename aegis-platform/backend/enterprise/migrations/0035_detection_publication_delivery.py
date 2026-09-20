from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0034_integration_live_acceptance'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DetectionPublicationDelivery',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('correlation_id', models.UUIDField()),
                ('package', models.JSONField()),
                ('package_sha256', models.CharField(max_length=64)),
                ('integration_configuration_fingerprint', models.CharField(max_length=64)),
                ('status', models.CharField(choices=[('queued','Queued'),('sending','Sending'),('delivered','Delivered'),('failed','Failed'),('blocked','Blocked')], default='queued', max_length=20)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('transport_status', models.PositiveIntegerField(blank=True, null=True)),
                ('response_sha256', models.CharField(blank=True, max_length=64)),
                ('last_error', models.TextField(blank=True)),
                ('sent_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('governed_request', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publication_delivery', to='enterprise.governedactionrequest')),
                ('integration', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publication_deliveries', to='enterprise.externalintegration')),
                ('live_acceptance', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publication_deliveries', to='enterprise.integrationliveacceptance')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publication_deliveries', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='detection_publication_deliveries', to='projects.project')),
                ('requested_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='requested_detection_publication_deliveries', to=settings.AUTH_USER_MODEL)),
                ('revision', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='publication_deliveries', to='enterprise.detectionrevision')),
            ],
            options={
                'ordering': ['created_at'],
                'indexes': [
                    models.Index(fields=['status','created_at'], name='idx_det_delivery_state'),
                    models.Index(fields=['revision','created_at'], name='idx_det_delivery_revision'),
                    models.Index(fields=['integration','status'], name='idx_det_delivery_target'),
                ],
            },
        ),
    ]
