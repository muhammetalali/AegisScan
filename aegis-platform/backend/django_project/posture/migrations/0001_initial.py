import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('projects', '0002_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PostureSnapshot',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('overall_score', models.FloatField()),
                ('rating', models.CharField(max_length=20)),
                ('vulnerability_health', models.FloatField()),
                ('control_effectiveness', models.FloatField()),
                ('evidence_quality', models.FloatField()),
                ('coverage', models.FloatField()),
                ('total_assets', models.PositiveIntegerField(default=0)),
                ('active_assets', models.PositiveIntegerField(default=0)),
                ('scanned_assets', models.PositiveIntegerField(default=0)),
                ('total_findings', models.PositiveIntegerField(default=0)),
                ('open_findings', models.PositiveIntegerField(default=0)),
                ('critical_findings', models.PositiveIntegerField(default=0)),
                ('high_findings', models.PositiveIntegerField(default=0)),
                ('medium_findings', models.PositiveIntegerField(default=0)),
                ('low_findings', models.PositiveIntegerField(default=0)),
                ('verified_findings', models.PositiveIntegerField(default=0)),
                ('evidence_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='posture_snapshots', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='posture_snapshots', to='projects.project')),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['project', '-created_at'], name='posture_snap_project_created_idx')],
            },
        ),
    ]
