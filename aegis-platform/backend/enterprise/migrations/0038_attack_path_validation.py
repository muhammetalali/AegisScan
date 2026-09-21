from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0037_threat_model_snapshot'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttackPathValidation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scenario_refs', models.JSONField(default=list)),
                ('evidence_refs', models.JSONField(default=list)),
                ('authorization_refs', models.JSONField(default=list)),
                ('relationship_refs', models.JSONField(default=list)),
                ('validation_sha256', models.CharField(editable=False, max_length=64, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('attack_path', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='validations', to='enterprise.attackpath')),
                ('blast_radius_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_path_validations', to='enterprise.blastradiussnapshot')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_path_validations', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_path_validations', to='projects.project')),
                ('threat_model_snapshot', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_path_validations', to='enterprise.threatmodelsnapshot')),
                ('validated_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='attack_path_validations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', '-created_at'], name='idx_apval_project_created'),
                    models.Index(fields=['attack_path', '-created_at'], name='idx_apval_path_created'),
                ],
            },
        ),
    ]
