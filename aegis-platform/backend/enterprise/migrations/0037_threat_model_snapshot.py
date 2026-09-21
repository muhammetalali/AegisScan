import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


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
                ('status', models.CharField(choices=[('completed', 'Completed'), ('failed', 'Failed')], default='completed', max_length=20)),
                ('methodologies', models.JSONField(default=list)),
                ('graph_sha256', models.CharField(max_length=64)),
                ('findings', models.JSONField(default=list)),
                ('summary', models.JSONField(default=dict)),
                ('snapshot_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='threat_model_snapshots', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='threat_model_snapshots', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [models.Index(fields=['project', '-created_at'], name='idx_threatmodel_project')],
            },
        ),
    ]
