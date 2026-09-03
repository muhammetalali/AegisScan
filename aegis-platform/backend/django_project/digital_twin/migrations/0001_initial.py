import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('assets', '0007_authorization_request_identity'),
        ('projects', '0002_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DigitalTwin',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('status', models.CharField(choices=[('building', 'Building'), ('ready', 'Ready'), ('drifted', 'Drifted'), ('failed', 'Failed')], default='building', max_length=20)),
                ('environment', models.JSONField(blank=True, default=dict)),
                ('built_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='digital_twins', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='digital_twins', to='projects.project')),
            ],
            options={
                'ordering': ['-updated_at'],
                'constraints': [models.UniqueConstraint(fields=('project', 'name'), name='dt_project_name_uniq')],
            },
        ),
        migrations.CreateModel(
            name='DigitalTwinNode',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('node_type', models.CharField(default='asset', max_length=40)),
                ('snapshot', models.JSONField(blank=True, default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='digital_twin_nodes', to='assets.asset')),
                ('twin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='nodes', to='digital_twin.digitaltwin')),
            ],
            options={
                'constraints': [models.UniqueConstraint(fields=('twin', 'asset'), name='dt_twin_asset_uniq')],
                'indexes': [models.Index(fields=['twin', 'asset'], name='dt_node_twin_asset_idx')],
            },
        ),
        migrations.CreateModel(
            name='TwinScenario',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('change_type', models.CharField(max_length=50)),
                ('description', models.TextField(blank=True)),
                ('parameters', models.JSONField(blank=True, default=dict)),
                ('affected_nodes', models.JSONField(blank=True, default=list)),
                ('security_impact', models.FloatField(blank=True, null=True)),
                ('performance_impact', models.FloatField(blank=True, null=True)),
                ('risk_reduction', models.FloatField(blank=True, null=True)),
                ('recommendation', models.TextField(blank=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('completed', 'Completed'), ('unsupported', 'Unsupported')], default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='twin_scenarios', to=settings.AUTH_USER_MODEL)),
                ('twin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scenarios', to='digital_twin.digitaltwin')),
            ],
            options={'ordering': ['-created_at']},
        ),
    ]
