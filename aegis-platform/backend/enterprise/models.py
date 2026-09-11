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


class ReportRecipientDelivery(models.Model):
    class Status(models.TextChoices):
        QUEUED='queued','Queued'; SENDING='sending','Sending'; SENT='sent','Sent'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    execution=models.ForeignKey(ReportScheduleExecution,on_delete=models.CASCADE,related_name='recipient_deliveries')
    recipient=models.EmailField(max_length=254)
    message_id=models.CharField(max_length=255,unique=True)
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.QUEUED)
    attempts=models.PositiveIntegerField(default=0)
    artifact_sha256=models.CharField(max_length=64,blank=True)
    last_error=models.TextField(blank=True)
    sent_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['execution','recipient'],name='unique_report_execution_recipient')]
        indexes=[models.Index(fields=['status','created_at']),models.Index(fields=['recipient','created_at'])]


class DecisionAction(models.Model):
    action_id=models.CharField(max_length=255,primary_key=True)
    organization=models.ForeignKey(Organization,on_delete=models.PROTECT,related_name='decision_actions',null=True,blank=True)
    project=models.ForeignKey('projects.Project',on_delete=models.PROTECT,related_name='decision_actions',null=True,blank=True)
    validation=models.ForeignKey('evidence.ValidationRun',on_delete=models.PROTECT,related_name='decision_actions',null=True,blank=True)
    decision_id=models.TextField(); node_id=models.TextField(); title=models.TextField(); owner=models.TextField(); requested_by=models.TextField()
    sla_hours=models.PositiveIntegerField(); state=models.TextField(); risk_before=models.IntegerField(default=0); confidence_before=models.IntegerField(default=0)
    priority=models.IntegerField(default=0); recommended_action=models.TextField(); remediation_plan=models.JSONField(default=list)
    created_at=models.DateTimeField(); updated_at=models.DateTimeField(); version=models.PositiveIntegerField(default=1)
    sla_status=models.TextField(default='on_track'); escalation_level=models.PositiveIntegerField(default=0)
    class Meta:
        db_table='security_decision_actions'
        indexes=[models.Index(fields=['state','updated_at'],name='idx_actions_state_updated'),models.Index(fields=['owner','sla_status','created_at'],name='idx_actions_owner_sla'),models.Index(fields=['requested_by'],name='idx_actions_requested_by'),models.Index(fields=['organization','state'],name='idx_actions_org_state'),models.Index(fields=['project','state'],name='idx_actions_project_state')]


class DecisionActionEvent(models.Model):
    event_id=models.BigAutoField(primary_key=True)
    action=models.ForeignKey(DecisionAction,db_column='action_id',to_field='action_id',on_delete=models.CASCADE,related_name='events')
    event_type=models.TextField(); actor=models.TextField(); note=models.TextField(null=True,blank=True); created_at=models.DateTimeField()
    class Meta:
        db_table='security_decision_action_events'; ordering=['event_id']
        indexes=[models.Index(fields=['action','created_at'],name='idx_action_events_created')]


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
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='assurance_schedules'); project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='assurance_schedules'); asset=models.ForeignKey('assets.Asset',on_delete=models.PROTECT,null=True,blank=True,related_name='assurance_schedules'); authorization_decision=models.ForeignKey('assets.AssetAuthorization',on_delete=models.PROTECT,null=True,blank=True,related_name='assurance_schedules'); scan_type=models.CharField(max_length=30); engine=models.CharField(max_length=30); interval_minutes=models.PositiveIntegerField(default=60); enabled=models.BooleanField(default=True); next_run=models.DateTimeField(); last_run=models.DateTimeField(null=True,blank=True); disabled_at=models.DateTimeField(null=True,blank=True); disabled_reason=models.TextField(blank=True); created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT); created_at=models.DateTimeField(auto_now_add=True)


class ContinuousAssuranceExecution(models.Model):
    """Durable, tenant-bound delivery record for one intended schedule occurrence."""

    class Status(models.TextChoices):
        PENDING='pending','Pending'; RUNNING='running','Running'; QUEUED='queued','Queued'; COMPLETED='completed','Completed'; BLOCKED='blocked','Blocked'; FAILED='failed','Failed'

    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    schedule=models.ForeignKey(ContinuousAssuranceSchedule,on_delete=models.CASCADE,related_name='executions')
    organization=models.ForeignKey(Organization,on_delete=models.PROTECT,related_name='assurance_executions')
    project=models.ForeignKey('projects.Project',on_delete=models.PROTECT,related_name='assurance_executions')
    asset=models.ForeignKey('assets.Asset',on_delete=models.PROTECT,related_name='assurance_executions')
    authorization_decision=models.ForeignKey('assets.AssetAuthorization',on_delete=models.PROTECT,related_name='assurance_executions')
    scheduled_for=models.DateTimeField()
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING)
    scan=models.OneToOneField('scans.Scan',on_delete=models.PROTECT,null=True,blank=True,related_name='assurance_execution')
    celery_task_id=models.CharField(max_length=255,blank=True)
    scanner_task_id=models.CharField(max_length=255,blank=True)
    attempts=models.PositiveIntegerField(default=0)
    reason=models.TextField(blank=True)
    started_at=models.DateTimeField(null=True,blank=True)
    completed_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    class Meta:
        constraints=[models.UniqueConstraint(fields=['schedule','scheduled_for'],name='uniq_assurance_schedule_occurrence')]
        indexes=[models.Index(fields=['schedule','status'],name='idx_assurance_schedule_state'),models.Index(fields=['organization','status'],name='idx_assurance_org_state')]


class Notification(models.Model):
    class Channel(models.TextChoices): IN_APP='in_app','In-App'; EMAIL='email','Email'; WEBHOOK='webhook','Webhook'; SLACK='slack','Slack'; TEAMS='teams','Teams'; SIEM='siem','SIEM'
    class Status(models.TextChoices): PENDING='pending','Pending'; SENDING='sending','Sending'; SENT='sent','Sent'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='notifications')
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True)
    source_security_event=models.ForeignKey('audit.SecurityEvent',on_delete=models.PROTECT,null=True,blank=True,related_name='notifications')
    channel=models.CharField(max_length=20,choices=Channel.choices)
    event_type=models.CharField(max_length=100)
    payload=models.JSONField(default=dict)
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING)
    attempts=models.PositiveIntegerField(default=0)
    last_error=models.TextField(blank=True)
    sent_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['source_security_event','user','channel'],name='uniq_security_event_recipient_channel')]
        indexes=[models.Index(fields=['status','updated_at'],name='idx_notification_delivery')]


class ExternalIntegration(models.Model):
    class Kind(models.TextChoices): SPLUNK='splunk','Splunk'; ELASTIC='elastic','Elastic'; SENTINEL='sentinel','Microsoft Sentinel'; QRADAR='qradar','IBM QRadar'; SOAR_WEBHOOK='soar_webhook','SOAR Webhook'; GITHUB='github','GitHub'; GITLAB='gitlab','GitLab'; BITBUCKET='bitbucket','Bitbucket'; ECR='ecr','AWS ECR'; GCR='gcr','Google Container/Artifact Registry'; ACR='acr','Azure Container Registry'; HARBOR='harbor','Harbor'; GHCR='ghcr','GitHub Container Registry'; GENERIC_WEBHOOK='generic_webhook','Generic Webhook'; SLACK='slack','Slack'; TEAMS='teams','Microsoft Teams'
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


# Enterprise gap-closure durable domain ----------------------------------------

class _AppendOnlyQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise RuntimeError('append-only records cannot be updated')

    def delete(self):
        raise RuntimeError('append-only records cannot be deleted')


class _AppendOnlyManager(models.Manager):
    def get_queryset(self):
        return _AppendOnlyQuerySet(self.model, using=self._db)


class Team(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='teams')
    name=models.CharField(max_length=160)
    slug=models.SlugField(max_length=180)
    parent=models.ForeignKey('self',on_delete=models.PROTECT,null=True,blank=True,related_name='children')
    description=models.TextField(blank=True)
    is_active=models.BooleanField(default=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['organization','slug'],name='uniq_team_org_slug')]
        indexes=[models.Index(fields=['organization','is_active'],name='idx_team_org_active')]


class TeamMembership(models.Model):
    class Role(models.TextChoices):
        LEAD='lead','Lead'; MEMBER='member','Member'; VIEWER='viewer','Viewer'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    team=models.ForeignKey(Team,on_delete=models.CASCADE,related_name='memberships')
    user=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='enterprise_team_memberships')
    role=models.CharField(max_length=20,choices=Role.choices,default=Role.MEMBER)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['team','user'],name='uniq_team_user')]
        indexes=[models.Index(fields=['user','role'],name='idx_team_user_role')]


class FindingDecisionProvenance(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.PROTECT,related_name='finding_decisions')
    project=models.ForeignKey('projects.Project',on_delete=models.PROTECT,related_name='finding_decisions')
    vulnerability=models.ForeignKey('vulnerabilities.Vulnerability',on_delete=models.PROTECT,related_name='decision_provenance')
    validation=models.ForeignKey('evidence.ValidationRun',on_delete=models.PROTECT,null=True,blank=True,related_name='finding_decisions')
    actor=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='finding_decisions')
    decision=models.CharField(max_length=80)
    old_status=models.CharField(max_length=20,blank=True)
    new_status=models.CharField(max_length=20,blank=True)
    policy_ref=models.CharField(max_length=240)
    reason=models.TextField()
    evidence_refs=models.JSONField(default=list)
    previous_hash=models.CharField(max_length=64,blank=True)
    entry_hash=models.CharField(max_length=64,unique=True)
    created_at=models.DateTimeField()
    objects=_AppendOnlyManager()
    class Meta:
        ordering=['created_at','id']
        indexes=[
            models.Index(fields=['vulnerability','created_at'],name='idx_find_decision_created'),
            models.Index(fields=['project','decision'],name='idx_find_decision_project'),
        ]
    def save(self,*args,**kwargs):
        if not self._state.adding:
            raise RuntimeError('finding decision provenance is immutable')
        return super().save(*args,**kwargs)
    def delete(self,*args,**kwargs):
        raise RuntimeError('finding decision provenance is immutable')


class ScanControlCheckpoint(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    scan=models.ForeignKey('scans.Scan',on_delete=models.CASCADE,related_name='control_checkpoints')
    sequence=models.PositiveIntegerField()
    state=models.CharField(max_length=20)
    phase=models.CharField(max_length=80,blank=True)
    engine=models.CharField(max_length=100,blank=True)
    progress=models.FloatField(default=0)
    task_id=models.CharField(max_length=255,blank=True)
    resume_token=models.UUIDField(default=uuid.uuid4,editable=False)
    metadata=models.JSONField(default=dict,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['scan','sequence'],name='uniq_scan_checkpoint_sequence')]
        indexes=[models.Index(fields=['scan','created_at'],name='idx_scan_checkpoint_created')]


class InvestigationCase(models.Model):
    class Status(models.TextChoices):
        OPEN='open','Open'; INVESTIGATING='investigating','Investigating'; DECIDED='decided','Decided'; CLOSED='closed','Closed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='investigation_cases')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='investigation_cases')
    title=models.CharField(max_length=240)
    description=models.TextField(blank=True)
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.OPEN)
    owner=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='owned_investigation_cases')
    findings=models.ManyToManyField('vulnerabilities.Vulnerability',blank=True,related_name='investigation_cases')
    evidence=models.ManyToManyField('evidence.Evidence',blank=True,related_name='investigation_cases')
    decision_summary=models.TextField(blank=True)
    closed_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        indexes=[
            models.Index(fields=['project','status'],name='idx_case_project_status'),
            models.Index(fields=['owner','status'],name='idx_case_owner_status'),
        ]


class InvestigationCaseEvent(models.Model):
    id=models.BigAutoField(primary_key=True)
    case=models.ForeignKey(InvestigationCase,on_delete=models.CASCADE,related_name='events')
    actor=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='investigation_case_events')
    event_type=models.CharField(max_length=80)
    payload=models.JSONField(default=dict)
    created_at=models.DateTimeField(auto_now_add=True)
    objects=_AppendOnlyManager()
    class Meta:
        ordering=['id']
    def save(self,*args,**kwargs):
        if not self._state.adding:
            raise RuntimeError('investigation case events are immutable')
        return super().save(*args,**kwargs)
    def delete(self,*args,**kwargs):
        raise RuntimeError('investigation case events are immutable')


class EvidenceGraphNode(models.Model):
    class Kind(models.TextChoices):
        ASSET='asset','Asset'; FINDING='finding','Finding'; EVIDENCE='evidence','Evidence'; SCAN='scan','Scan'; VALIDATION='validation','Validation'; REMEDIATION='remediation','Remediation'; USER='user','User'; AUDIT='audit','Audit'; CONTROL='control','Control'; THREAT='threat','Threat'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='evidence_graph_nodes')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='evidence_graph_nodes')
    kind=models.CharField(max_length=20,choices=Kind.choices)
    external_ref=models.CharField(max_length=255)
    label=models.CharField(max_length=300)
    confidence=models.FloatField(default=1.0)
    properties=models.JSONField(default=dict,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['project','kind','external_ref'],name='uniq_egraph_project_kind_ref')]
        indexes=[models.Index(fields=['project','kind'],name='idx_egraph_project_kind')]


class EvidenceGraphEdge(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='evidence_graph_edges')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='evidence_graph_edges')
    source=models.ForeignKey(EvidenceGraphNode,on_delete=models.CASCADE,related_name='outgoing_edges')
    target=models.ForeignKey(EvidenceGraphNode,on_delete=models.CASCADE,related_name='incoming_edges')
    edge_type=models.CharField(max_length=60)
    weight=models.FloatField(default=1.0)
    evidence_refs=models.JSONField(default=list,blank=True)
    properties=models.JSONField(default=dict,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['project','source','target','edge_type'],name='uniq_egraph_edge')]
        indexes=[models.Index(fields=['project','edge_type'],name='idx_egraph_project_edge')]


class BlastRadiusSnapshot(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='blast_radius_snapshots')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='blast_radius_snapshots')
    attack_path=models.ForeignKey(AttackPath,on_delete=models.SET_NULL,null=True,blank=True,related_name='blast_radius_snapshots')
    root_ref=models.CharField(max_length=255)
    crown_jewel_refs=models.JSONField(default=list)
    impacted_nodes=models.JSONField(default=list)
    score=models.FloatField(default=0)
    evidence_refs=models.JSONField(default=list)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        indexes=[models.Index(fields=['project','created_at'],name='idx_blast_project_created')]


class ArtifactIntegrityRecord(models.Model):
    class State(models.TextChoices):
        TRUSTED='trusted','Trusted'; REVIEW='review','Review'; QUARANTINED='quarantined','Quarantined'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='artifact_integrity_records')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='artifact_integrity_records')
    artifact_type=models.CharField(max_length=40)
    name=models.CharField(max_length=300)
    source_ref=models.CharField(max_length=700)
    sha256=models.CharField(max_length=64)
    signature_verified=models.BooleanField(default=False)
    provenance_verified=models.BooleanField(default=False)
    package_namespace=models.CharField(max_length=300,blank=True)
    state=models.CharField(max_length=20,choices=State.choices,default=State.REVIEW)
    quarantine_reason=models.TextField(blank=True)
    metadata=models.JSONField(default=dict,blank=True)
    created_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='artifact_integrity_records')
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['project','sha256'],name='uniq_project_artifact_sha')]
        indexes=[models.Index(fields=['project','state'],name='idx_artifact_project_state')]


class AdaptiveWeightProfile(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='adaptive_weight_profiles')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='adaptive_weight_profiles')
    version=models.PositiveIntegerField()
    weights=models.JSONField(default=dict)
    learned_from=models.PositiveIntegerField(default=0)
    reward_mean=models.FloatField(default=0)
    algorithm=models.CharField(max_length=80,default='bounded-contextual-feedback-v1')
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['project','version'],name='uniq_project_weight_version')]


class FormalPolicyProof(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='formal_policy_proofs')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='formal_policy_proofs')
    proof_type=models.CharField(max_length=80)
    input_sha256=models.CharField(max_length=64)
    satisfiable=models.BooleanField()
    model=models.JSONField(default=dict,blank=True)
    solver=models.CharField(max_length=80,default='z3')
    solver_version=models.CharField(max_length=80,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        indexes=[models.Index(fields=['project','proof_type','created_at'],name='idx_formal_proof_project')]


# External integration and plugin lifecycle ------------------------------------

class IntegrationSyncRun(models.Model):
    class Status(models.TextChoices):
        PENDING='pending','Pending'; RUNNING='running','Running'; COMPLETED='completed','Completed'; FAILED='failed','Failed'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,related_name='integration_sync_runs')
    project=models.ForeignKey('projects.Project',on_delete=models.CASCADE,related_name='integration_sync_runs')
    integration=models.ForeignKey(ExternalIntegration,on_delete=models.CASCADE,related_name='sync_runs')
    sync_type=models.CharField(max_length=40)
    status=models.CharField(max_length=20,choices=Status.choices,default=Status.PENDING)
    cursor=models.CharField(max_length=500,blank=True)
    records_count=models.PositiveIntegerField(default=0)
    summary=models.JSONField(default=dict,blank=True)
    error_message=models.TextField(blank=True)
    requested_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.PROTECT,related_name='integration_sync_runs')
    started_at=models.DateTimeField(null=True,blank=True)
    completed_at=models.DateTimeField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True)
    class Meta:
        indexes=[
            models.Index(fields=['integration','status'],name='idx_integration_sync_state'),
            models.Index(fields=['project','created_at'],name='idx_integration_sync_project'),
        ]


class ExternalIntelligenceSnapshot(models.Model):
    class Provider(models.TextChoices):
        SHODAN='shodan','Shodan'; CENSYS='censys','Censys'; GREYNOISE='greynoise','GreyNoise'
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    provider=models.CharField(max_length=20,choices=Provider.choices)
    indicator=models.CharField(max_length=255)
    data=models.JSONField(default=dict)
    source_url=models.URLField(max_length=1000)
    snapshot_sha256=models.CharField(max_length=64)
    observed_by=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True,related_name='external_intelligence_snapshots')
    observed_at=models.DateTimeField()
    class Meta:
        ordering=['-observed_at','-id']
        indexes=[
            models.Index(fields=['provider','indicator','observed_at'],name='idx_extintel_prov_ind'),
            models.Index(fields=['indicator','observed_at'],name='idx_extintel_ind_time'),
        ]


class PluginPackage(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    name=models.CharField(max_length=160)
    version=models.CharField(max_length=80)
    source=models.URLField(max_length=1000)
    digest=models.CharField(max_length=64)
    manifest=models.JSONField(default=dict)
    dependencies=models.JSONField(default=list)
    approved=models.BooleanField(default=False)
    enabled=models.BooleanField(default=False)
    installed_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    class Meta:
        constraints=[models.UniqueConstraint(fields=['name','version'],name='uniq_plugin_package_version')]
        indexes=[
            models.Index(fields=['name','enabled'],name='idx_plugin_package_enabled'),
            models.Index(fields=['approved','enabled'],name='idx_plugin_package_approved'),
        ]
