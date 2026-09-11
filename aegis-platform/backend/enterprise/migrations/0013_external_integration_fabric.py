import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0012_enterprise_gap_closure'),
        ('projects', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='externalintegration',
            name='kind',
            field=models.CharField(
                choices=[
                    ('splunk','Splunk'),('elastic','Elastic'),('sentinel','Microsoft Sentinel'),
                    ('qradar','IBM QRadar'),('soar_webhook','SOAR Webhook'),
                    ('github','GitHub'),('gitlab','GitLab'),('bitbucket','Bitbucket'),
                    ('ecr','AWS ECR'),('gcr','Google Container/Artifact Registry'),
                    ('acr','Azure Container Registry'),('harbor','Harbor'),('ghcr','GitHub Container Registry'),
                    ('generic_webhook','Generic Webhook'),('slack','Slack'),('teams','Microsoft Teams'),
                ],
                max_length=30,
            ),
        ),
        migrations.CreateModel(
            name='ExternalIntelligenceSnapshot',
            fields=[
                ('id',models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ('provider',models.CharField(choices=[('shodan','Shodan'),('censys','Censys'),('greynoise','GreyNoise')],max_length=20)),
                ('indicator',models.CharField(max_length=255)),
                ('data',models.JSONField(default=dict)),
                ('source_url',models.URLField(max_length=1000)),
                ('snapshot_sha256',models.CharField(max_length=64)),
                ('observed_at',models.DateTimeField()),
                ('observed_by',models.ForeignKey(blank=True,null=True,on_delete=django.db.models.deletion.SET_NULL,related_name='external_intelligence_snapshots',to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering':['-observed_at','-id']},
        ),
        migrations.CreateModel(
            name='PluginPackage',
            fields=[
                ('id',models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ('name',models.CharField(max_length=160)),
                ('version',models.CharField(max_length=80)),
                ('source',models.URLField(max_length=1000)),
                ('digest',models.CharField(max_length=64)),
                ('manifest',models.JSONField(default=dict)),
                ('dependencies',models.JSONField(default=list)),
                ('approved',models.BooleanField(default=False)),
                ('enabled',models.BooleanField(default=False)),
                ('installed_at',models.DateTimeField(auto_now_add=True)),
                ('updated_at',models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='IntegrationSyncRun',
            fields=[
                ('id',models.UUIDField(default=uuid.uuid4,editable=False,primary_key=True,serialize=False)),
                ('sync_type',models.CharField(max_length=40)),
                ('status',models.CharField(choices=[('pending','Pending'),('running','Running'),('completed','Completed'),('failed','Failed')],default='pending',max_length=20)),
                ('cursor',models.CharField(blank=True,max_length=500)),
                ('records_count',models.PositiveIntegerField(default=0)),
                ('summary',models.JSONField(blank=True,default=dict)),
                ('error_message',models.TextField(blank=True)),
                ('started_at',models.DateTimeField(blank=True,null=True)),
                ('completed_at',models.DateTimeField(blank=True,null=True)),
                ('created_at',models.DateTimeField(auto_now_add=True)),
                ('integration',models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name='sync_runs',to='enterprise.externalintegration')),
                ('organization',models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name='integration_sync_runs',to='enterprise.organization')),
                ('project',models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name='integration_sync_runs',to='projects.project')),
                ('requested_by',models.ForeignKey(on_delete=django.db.models.deletion.PROTECT,related_name='integration_sync_runs',to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddIndex(
            model_name='externalintelligencesnapshot',
            index=models.Index(fields=['provider','indicator','observed_at'],name='idx_extintel_provider_indicator'),
        ),
        migrations.AddIndex(
            model_name='externalintelligencesnapshot',
            index=models.Index(fields=['indicator','observed_at'],name='idx_extintel_indicator_time'),
        ),
        migrations.AddConstraint(
            model_name='pluginpackage',
            constraint=models.UniqueConstraint(fields=('name','version'),name='uniq_plugin_package_version'),
        ),
        migrations.AddIndex(
            model_name='pluginpackage',
            index=models.Index(fields=['name','enabled'],name='idx_plugin_package_enabled'),
        ),
        migrations.AddIndex(
            model_name='pluginpackage',
            index=models.Index(fields=['approved','enabled'],name='idx_plugin_package_approved'),
        ),
        migrations.AddIndex(
            model_name='integrationsyncrun',
            index=models.Index(fields=['integration','status'],name='idx_integration_sync_state'),
        ),
        migrations.AddIndex(
            model_name='integrationsyncrun',
            index=models.Index(fields=['project','created_at'],name='idx_integration_sync_project'),
        ),
    ]
