from __future__ import annotations

import django.db.models.deletion
import uuid

from django.conf import settings
from django.db import migrations, models


def install_event_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute("""
        CREATE FUNCTION aegis_web_lab_lifecycle_event_immutable() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Web Lab lifecycle events are immutable';
        END;
        $$;
        CREATE TRIGGER trg_web_lab_lifecycle_event_immutable
        BEFORE UPDATE OR DELETE ON enterprise_weblablifecycleevent
        FOR EACH ROW EXECUTE FUNCTION aegis_web_lab_lifecycle_event_immutable();
    """)


def remove_event_immutability(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute(
        'DROP TRIGGER IF EXISTS trg_web_lab_lifecycle_event_immutable '
        'ON enterprise_weblablifecycleevent;')
    schema_editor.execute(
        'DROP FUNCTION IF EXISTS aegis_web_lab_lifecycle_event_immutable();')


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0050_web_lab_evidence_immutability'),
        ('evidence', '0008_governed_oast_runtime'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='WebLabInstance',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('definition_id', models.CharField(max_length=80)),
                ('fixture_revision', models.CharField(editable=False, max_length=64)),
                ('variant', models.CharField(max_length=24)),
                ('generation', models.PositiveIntegerField(default=1)),
                ('instance_ref', models.UUIDField(editable=False, unique=True)),
                ('image_id', models.CharField(editable=False, max_length=71)),
                ('container_id', models.CharField(editable=False, max_length=64)),
                ('container_name', models.CharField(editable=False, max_length=96)),
                ('target', models.CharField(editable=False, max_length=500)),
                ('status', models.CharField(choices=[('ready', 'Ready'), ('expired', 'Expired'), ('cleaned', 'Cleaned'), ('failed', 'Failed')], default='ready', max_length=20)),
                ('expires_at', models.DateTimeField()),
                ('cleaned_at', models.DateTimeField(blank=True, null=True)),
                ('version', models.PositiveIntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('asset', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_instances', to='assets.asset')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_instances', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_instances', to='projects.project')),
                ('provisioned_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='provisioned_web_lab_instances', to=settings.AUTH_USER_MODEL)),
                ('runtime_evidence', models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_instance', to='evidence.evidence')),
                ('supersedes', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='reset_successors', to='enterprise.weblabinstance')),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['project', 'asset', 'status'], name='idx_weblab_project_asset'),
                    models.Index(fields=['expires_at', 'status'], name='idx_weblab_expiry_status'),
                    models.Index(fields=['definition_id', 'fixture_revision'], name='idx_weblab_definition_rev'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('project', 'asset', 'definition_id', 'generation'), name='uniq_weblab_generation'),
                    models.CheckConstraint(condition=models.Q(('generation__gte', 1)), name='weblab_generation_gte_1'),
                    models.CheckConstraint(condition=models.Q(('version__gte', 1)), name='weblab_version_gte_1'),
                    models.CheckConstraint(condition=models.Q(models.Q(('cleaned_at__isnull', False), ('status', 'cleaned')), models.Q(models.Q(('status', 'cleaned'), _negated=True), ('cleaned_at__isnull', True)), _connector='OR'), name='weblab_cleaned_shape'),
                ],
            },
        ),
        migrations.CreateModel(
            name='WebLabLifecycleEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('sequence', models.PositiveIntegerField()),
                ('event_type', models.CharField(choices=[('provisioned', 'Provisioned'), ('expired', 'Expired'), ('cleaned', 'Cleaned'), ('failed', 'Failed')], max_length=24)),
                ('idempotency_key', models.CharField(editable=False, max_length=128)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64)),
                ('before_status', models.CharField(blank=True, max_length=20)),
                ('after_status', models.CharField(max_length=20)),
                ('generation', models.PositiveIntegerField()),
                ('details', models.JSONField(default=dict)),
                ('previous_hash', models.CharField(blank=True, editable=False, max_length=64)),
                ('entry_hash', models.CharField(editable=False, max_length=64, unique=True)),
                ('occurred_at', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_lifecycle_events', to=settings.AUTH_USER_MODEL)),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='lifecycle_events', to='enterprise.weblabinstance')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_lifecycle_events', to='enterprise.organization')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_lifecycle_events', to='projects.project')),
                ('runtime_evidence', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='web_lab_lifecycle_events', to='evidence.evidence')),
            ],
            options={
                'ordering': ['sequence', 'occurred_at', 'id'],
                'indexes': [
                    models.Index(fields=['project', 'event_type', '-occurred_at'], name='idx_weblab_event_project'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('instance', 'sequence'), name='uniq_weblab_event_sequence'),
                    models.UniqueConstraint(fields=('organization', 'idempotency_key'), name='uniq_weblab_org_idem'),
                    models.CheckConstraint(condition=models.Q(('sequence__gte', 1)), name='weblab_event_sequence_gte_1'),
                    models.CheckConstraint(condition=models.Q(('generation__gte', 1)), name='weblab_event_generation_gte_1'),
                ],
            },
        ),
        migrations.RunPython(install_event_immutability, remove_event_immutability),
    ]
