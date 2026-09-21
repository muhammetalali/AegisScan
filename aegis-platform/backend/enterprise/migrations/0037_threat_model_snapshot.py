from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0036_governed_work_queue'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ThreatModelSnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=240)),
                ('methodologies', models.JSONField(default=list)),
                ('pasta_stage', models.PositiveSmallIntegerField()),
                ('scope', models.JSONField(default=dict)),
                ('scenarios', models.JSONField(default=list)),
                ('architecture_sha256', models.CharField(max_length=64)),
                ('model_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='threat_model_snapshots', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='threat_model_snapshots', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='threat_model_snapshots', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', '-created_at'], name='idx_threatmodel_project'),
                    models.Index(fields=['project', 'pasta_stage'], name='idx_threatmodel_pasta'),
                ],
            },
        ),
    ]
