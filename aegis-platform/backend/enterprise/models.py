from __future__ import annotations

import uuid
from django.conf import settings
from django.db import models


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=220, unique=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='owned_organizations')
    is_active = models.BooleanField(default=True)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta: ordering = ['name']


class OrganizationMembership(models.Model):
    class Role(models.TextChoices):
        OWNER='owner','Owner'; ADMIN='admin','Admin'; MANAGER='manager','Manager'; ANALYST='analyst','Analyst'; AUDITOR='auditor','Auditor'; VIEWER='viewer','Viewer'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='memberships')
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='organization_memberships')
    role=models.CharField(max_length=20,choices=Role.choices)
    is_active=models.BooleanField(default=True)
    created_at=models.DateTimeField(auto_now_add=True); updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        unique_together=['organization','user']
        indexes=[models.Index(fields=['user','is_active']),models.Index(fields=['organization','role'])]


class TenantProject(models.Model):
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='project_links')
    project=models.OneToOneField('projects.Project',on_delete=models.CASCADE,related_name='tenant_link')
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['organization','project'],name='uniq_org_project')]


class DigitalTwin(models.Model):
    class Status(models.TextChoices): BUILDING='building','Building'; READY='ready','Ready'; STALE='stale','Stale'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='digital_twins')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='digital_twins')
    name=models.CharField(max_length=200); status=models.CharField(max_length=20,choices=Status.choices,default=Status.BUILDING)
    version=models.PositiveIntegerField(default=1)
    source_scan=models.ForeignKey('scans.Scan',on_delete=models.SET_NULL,null=True,blank=True,related_name='digital_twins')
    snapshot=models.JSONField(default=dict,blank=True); built_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True); updated_at=models.DateTimeField(auto_now=True)


class TwinNode(models.Model):
    class Kind(models.TextChoices): ASSET='asset','Asset'; SERVICE='service','Service'; IDENTITY='identity','Identity'; FINDING='finding','Finding'; VULNERABILITY='vulnerability','Vulnerability'; PRIVILEGE='privilege','Privilege'; RESOURCE='resource','Resource'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); twin=models.ForeignKey(DigitalTwin,on_delete=models.CASCADE,related_name='nodes')
    kind=models.CharField(max_length=20,choices=Kind.choices); external_id=models.CharField(max_length=100); name=models.CharField(max_length=300); properties=models.JSONField(default=dict,blank=True)
    class Meta: unique_together=['twin','kind','external_id']; indexes=[models.Index(fields=['twin','kind'])]


class TwinRelationship(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); twin=models.ForeignKey(DigitalTwin,on_delete=models.CASCADE,related_name='relationships')
    source=models.ForeignKey(TwinNode,on_delete=models.CASCADE,related_name='outgoing'); target=models.ForeignKey(TwinNode,on_delete=models.CASCADE,related_name='incoming')
    relationship_type=models.CharField(max_length=40); properties=models.JSONField(default=dict,blank=True)
    class Meta: unique_together=['twin','source','target','relationship_type']


class TwinScenario(models.Model):
    class Status(models.TextChoices): PENDING='pending','Pending'; RUNNING='running','Running'; COMPLETED='completed','Completed'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); twin=models.ForeignKey(DigitalTwin,on_delete=models.CASCADE,related_name='scenarios')
    name=models.CharField(max_length=200); change_type=models.CharField(max_length=60); description=models.TextField(blank=True); parameters=models.JSONField(default=dict,blank=True)
    affected_nodes=models.JSONField(default=list,blank=True); baseline_risk=models.FloatField(null=True,blank=True); predicted_risk=models.FloatField(null=True,blank=True); risk_delta=models.FloatField(null=True,blank=True)
    evidence=models.JSONField(default=dict,blank=True); recommendation=models.TextField(blank=True); status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING)
    created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True); completed_at=models.DateTimeField(null=True,blank=True)


class ReportSchedule(models.Model):
    class Frequency(models.TextChoices): DAILY='daily','Daily'; WEEKLY='weekly','Weekly'; MONTHLY='monthly','Monthly'; CRON='cron','Cron'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='report_schedules'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='report_schedules')
    title=models.CharField(max_length=200); report_type=models.CharField(max_length=30,default='full'); format=models.CharField(max_length=10,default='pdf'); frequency=models.CharField(max_length=20,choices=Frequency.choices); cron_expression=models.CharField(max_length=120,blank=True)
    recipients=models.JSONField(default=list); enabled=models.BooleanField(default=True); next_run=models.DateTimeField(); last_run=models.DateTimeField(null=True,blank=True); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True); updated_at=models.DateTimeField(auto_now=True)


class ReportScheduleExecution(models.Model):
    class Status(models.TextChoices):
        PENDING='pending','Pending'; RUNNING='running','Running'; COMPLETED='completed','Completed'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    schedule=models.ForeignKey(ReportSchedule,on_delete=models.CASCADE,related_name='executions')
    delivery_id=models.CharField(max_length=255,unique=True)
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING)
    report=models.OneToOneField('audit.DataExport',on_delete=models.PROTECT,related_name='schedule_execution',null=True,blank=True)
    attempts=models.PositiveIntegerField(default=0)
    error_message=models.TextField(blank=True)
    started_at=models.DateTimeField(null=True,blank=True)
    completed_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        indexes=[models.Index(fields=['schedule','status']),models.Index(fields=['created_at'])]


class ThreatIntelCache(models.Model):
    provider=models.CharField(max_length=30); key=models.CharField(max_length=300); payload=models.JSONField(default=dict); fetched_at=models.DateTimeField(); expires_at=models.DateTimeField(); http_status=models.PositiveIntegerField(null=True,blank=True); etag=models.CharField(max_length=200,blank=True); sha256=models.CharField(max_length=64,blank=True)
    class Meta: unique_together=['provider','key']; indexes=[models.Index(fields=['provider','expires_at'])]


class ThreatIntelAudit(models.Model):
    provider=models.CharField(max_length=30); operation=models.CharField(max_length=30); key=models.CharField(max_length=300); request_metadata=models.JSONField(default=dict,blank=True); response_status=models.PositiveIntegerField(null=True,blank=True); duration_ms=models.PositiveIntegerField(default=0); error_message=models.TextField(blank=True); created_at=models.DateTimeField(auto_now_add=True)


class FindingIntelligence(models.Model):
    vulnerability=models.OneToOneField('vulnerabilities.Vulnerability',on_delete=models.CASCADE,related_name='intelligence')
    source_snapshot=models.ForeignKey('intelligence.IntelligenceEnrichment',on_delete=models.PROTECT,related_name='finding_analyses',null=True,blank=True)
    primary_cve=models.CharField(max_length=32,blank=True,db_index=True)
    analysis_version=models.CharField(max_length=20,default='1.0')
    nvd=models.JSONField(default=dict,blank=True); osv=models.JSONField(default=dict,blank=True); cisa_kev=models.JSONField(default=dict,blank=True); epss=models.JSONField(default=dict,blank=True); confidence=models.FloatField(default=0.0); conflict=models.BooleanField(default=False); explanation=models.TextField(blank=True); recommendation=models.TextField(blank=True); calculated_at=models.DateTimeField(auto_now=True)


class AttackPath(models.Model):
    class Status(models.TextChoices): DISCOVERED='discovered','Discovered'; VALIDATED='validated','Validated'; CLOSED='closed','Closed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='attack_paths'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='attack_paths')
    source_node=models.JSONField(default=dict); target_node=models.JSONField(default=dict); steps=models.JSONField(default=list); risk_score=models.FloatField(default=0.0); evidence=models.JSONField(default=dict,blank=True); status=models.CharField(max_length=20,choices=Status.choices,default=Status.DISCOVERED); discovered_at=models.DateTimeField(auto_now_add=True); updated_at=models.DateTimeField(auto_now=True)


class ComplianceMapping(models.Model):
    assessment=models.ForeignKey('compliance.ComplianceAssessment',on_delete=models.CASCADE,related_name='automatic_mappings'); vulnerability=models.ForeignKey('vulnerabilities.Vulnerability',on_delete=models.CASCADE,related_name='compliance_mappings'); mapping_reason=models.TextField(); confidence=models.FloatField(default=0.0); source=models.CharField(max_length=50,default='rule'); created_at=models.DateTimeField(auto_now_add=True)
    class Meta: unique_together=['assessment','vulnerability']


class ExecutiveSnapshot(models.Model):
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='executive_snapshots'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='executive_snapshots'); score=models.FloatField(default=0); risk=models.FloatField(default=0); critical_findings=models.PositiveIntegerField(default=0); high_findings=models.PositiveIntegerField(default=0); open_findings=models.PositiveIntegerField(default=0); validated_findings=models.PositiveIntegerField(default=0); fixed_findings=models.PositiveIntegerField(default=0); compliance_score=models.FloatField(default=0); coverage_score=models.FloatField(default=0); trend=models.CharField(max_length=20,default='stable'); deltas=models.JSONField(default=dict,blank=True); source_scan=models.ForeignKey('scans.Scan',on_delete=models.SET_NULL,null=True,blank=True); captured_at=models.DateTimeField(auto_now_add=True)


class ContinuousAssuranceSchedule(models.Model):
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='assurance_schedules'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='assurance_schedules'); asset=models.ForeignKey('assets.Asset',on_delete=models.PROTECT,null=True,blank=True,related_name='assurance_schedules'); authorization_decision=models.ForeignKey('assets.AssetAuthorization',on_delete=models.PROTECT,null=True,blank=True,related_name='assurance_schedules'); scan_type=models.CharField(max_length=30); engine=models.CharField(max_length=30); interval_minutes=models.PositiveIntegerField(default=60); enabled=models.BooleanField(default=True); next_run=models.DateTimeField(); last_run=models.DateTimeField(null=True,blank=True); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True)


class Notification(models.Model):
    class Channel(models.TextChoices): EMAIL='email','Email'; WEBHOOK='webhook','Webhook'; SLACK='slack','Slack'; TEAMS='teams','Teams'; SIEM='siem','SIEM'
    class Status(models.TextChoices): PENDING='pending','Pending'; SENT='sent','Sent'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False); organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='notifications'); user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True); channel=models.CharField(max_length=20,choices=Channel.choices); event_type=models.CharField(max_length=100); payload=models.JSONField(default=dict); status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING); attempts=models.PositiveIntegerField(default=0); last_error=models.TextField(blank=True); sent_at=models.DateTimeField(null=True,blank=True); created_at=models.DateTimeField(auto_now_add=True)


class ExternalIntegration(models.Model):
    class Kind(models.TextChoices): SPLUNK='splunk','Splunk'; ELASTIC='elastic','Elastic'; GENERIC_WEBHOOK='generic_webhook','Generic Webhook'; SLACK='slack','Slack'; TEAMS='teams','Microsoft Teams'
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='integrations'); kind=models.CharField(max_length=30,choices=Kind.choices); name=models.CharField(max_length=120); base_url=models.URLField(); secret_ref=models.CharField(max_length=200,blank=True); config=models.JSONField(default=dict,blank=True); enabled=models.BooleanField(default=True); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True); updated_at=models.DateTimeField(auto_now=True)


class CloudDiscoveryRun(models.Model):
    class Provider(models.TextChoices): AWS='aws','AWS'; AZURE='azure','Azure'; GCP='gcp','GCP'
    class Status(models.TextChoices): PENDING='pending','Pending'; RUNNING='running','Running'; COMPLETED='completed','Completed'; FAILED='failed','Failed'
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='cloud_discovery_runs'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='cloud_discovery_runs'); provider=models.CharField(max_length=20,choices=Provider.choices); config=models.JSONField(default=dict,blank=True); status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING); resources=models.JSONField(default=list,blank=True); error_message=models.TextField(blank=True); started_at=models.DateTimeField(null=True,blank=True); completed_at=models.DateTimeField(null=True,blank=True); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True)


class SBOMArtifact(models.Model):
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='sboms'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='sboms'); source=models.CharField(max_length=30); source_ref=models.CharField(max_length=500); format=models.CharField(max_length=30); sha256=models.CharField(max_length=64); component_count=models.PositiveIntegerField(default=0); document=models.JSONField(default=dict); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True)


class SBOMComponent(models.Model):
    artifact=models.ForeignKey(SBOMArtifact,on_delete=models.CASCADE,related_name='components'); name=models.CharField(max_length=300); version=models.CharField(max_length=200,blank=True); ecosystem=models.CharField(max_length=100,blank=True); purl=models.CharField(max_length=500,blank=True); licenses=models.JSONField(default=list,blank=True); hashes=models.JSONField(default=list,blank=True); vulnerabilities=models.JSONField(default=list,blank=True)
    class Meta: indexes=[models.Index(fields=['name','version'])]
