from __future__ import annotations

import json
from datetime import timedelta

from asgiref.sync import async_to_sync
from celery import shared_task
from django.core.mail import send_mail
from django.utils import timezone

from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from .models import ContinuousAssuranceSchedule, Notification, ReportSchedule, CloudDiscoveryRun, ExternalIntegration
from .services import build_twin, predict_scenario, generate_attack_paths, map_compliance, fetch_intel, fuse_finding
from .integrations import send_integration, ingest_sbom

@shared_task(name='enterprise.build_digital_twin')
def build_digital_twin_task(twin_id: str): return {'twin_id': str(build_twin(twin_id).id), 'status':'ready'}

@shared_task(name='enterprise.predict_digital_twin_scenario')
def predict_digital_twin_scenario_task(scenario_id: str):
    from .models import TwinScenario
    return {'scenario_id':str(predict_scenario(TwinScenario.objects.get(pk=scenario_id)).id),'status':'completed'}

@shared_task(name='enterprise.generate_attack_paths')
def generate_attack_paths_task(project_id: str, organization_id: str):
    from .models import Organization
    project=Project.objects.get(pk=project_id); paths=generate_attack_paths(project,Organization.objects.get(pk=organization_id)); return {'project_id':project_id,'paths_created':len(paths)}

@shared_task(name='enterprise.map_compliance')
def map_compliance_task(project_id: str): return {'project_id':project_id,'mappings_created':map_compliance(Project.objects.get(pk=project_id))}

@shared_task(name='enterprise.fuse_finding_intelligence')
def fuse_finding_intelligence_task(finding_id: str):
    item=fuse_finding(Vulnerability.objects.get(pk=finding_id)); return {'finding_id':finding_id,'confidence':item.confidence,'conflict':item.conflict,'source_snapshot_id':str(item.source_snapshot_id),'primary_cve':item.primary_cve,'analysis_version':item.analysis_version}

@shared_task(name='enterprise.fetch_threat_intel')
def fetch_threat_intel_task(provider: str,key: str,cve: str|None=None,package: dict|None=None): return fetch_intel(provider,key,cve=cve,package=package)

@shared_task(name='enterprise.execute_report_schedule')
def execute_report_schedule(schedule_id: str):
    from fastapi_app.routers.reports import ReportCreate, _build_payload, _create_report
    schedule=ReportSchedule.objects.select_related('project').get(pk=schedule_id)
    if not schedule.enabled:return {'status':'disabled','schedule_id':schedule_id}
    payload=async_to_sync(_build_payload)(str(schedule.project_id),None,schedule.report_type)
    report=async_to_sync(_create_report)(ReportCreate(project_id=str(schedule.project_id),title=schedule.title,report_type=schedule.report_type,format=schedule.format),str(schedule.created_by_id),payload)
    now=timezone.now(); schedule.last_run=now; schedule.next_run=now+timedelta(minutes={'daily':1440,'weekly':10080,'monthly':43200}.get(schedule.frequency,60)); schedule.save(update_fields=['last_run','next_run','updated_at'])
    return {'status':'completed','schedule_id':schedule_id,'report_id':str(report.id)}

@shared_task(name='enterprise.send_notification',autoretry_for=(Exception,),retry_backoff=True,max_retries=3)
def send_notification(notification_id: str):
    n=Notification.objects.select_related('user','organization').get(pk=notification_id); n.attempts+=1
    try:
        if n.channel==Notification.Channel.EMAIL:
            if not n.user or not n.user.email: raise ValueError('Email notification requires a recipient user')
            send_mail(n.event_type,json.dumps(n.payload,ensure_ascii=False,indent=2),None,[n.user.email],fail_silently=False)
        else:
            url=str(n.payload.get('url') or '').strip()
            if not url: raise ValueError('Webhook-style notification requires payload.url')
            import requests
            response=requests.post(url,json=n.payload.get('body',n.payload),timeout=15); response.raise_for_status()
        n.status=Notification.Status.SENT; n.sent_at=timezone.now(); n.last_error=''; n.save(update_fields=['attempts','status','sent_at','last_error']); return {'status':'sent','notification_id':notification_id}
    except Exception as exc:
        n.status=Notification.Status.FAILED; n.last_error=str(exc); n.save(update_fields=['attempts','status','last_error']); raise

@shared_task(name='enterprise.dispatch_integration')
def dispatch_integration(integration_id: str,event: dict): return send_integration(ExternalIntegration.objects.get(pk=integration_id),event)

@shared_task(name='enterprise.run_continuous_assurance')
def run_continuous_assurance(schedule_id: str):
    schedule=ContinuousAssuranceSchedule.objects.select_related('project','asset','authorization_decision').get(pk=schedule_id)
    if not schedule.enabled:return {'status':'disabled','schedule_id':schedule_id}
    from django_project.scans.models import Scan
    from fastapi_app.tasks.security_scan import run_nmap_scan,run_nuclei_scan
    from fastapi_app.tasks.advanced_scans import run_masscan_scan,run_semgrep_scan
    task={'nmap':run_nmap_scan,'nuclei':run_nuclei_scan,'masscan':run_masscan_scan,'semgrep':run_semgrep_scan}.get(schedule.engine)
    if not task: raise ValueError(f'Unsupported assurance engine: {schedule.engine}')
    asset=schedule.asset
    if not asset or not asset.is_active or asset.project_id != schedule.project_id:
        raise ValueError('Continuous assurance requires its persisted active project asset binding')
    from fastapi_app.services.authorization_guard import current_asset_authorization
    authorization, reason=current_asset_authorization(asset)
    if authorization is None or authorization.id != schedule.authorization_decision_id:
        raise ValueError(reason or 'Continuous assurance authorization was superseded; renew the schedule binding')
    scan=Scan.objects.create(project=schedule.project,name=f'Continuous assurance {schedule.engine}',scan_type=schedule.scan_type,asset=asset,authorization_decision=authorization,engines=[schedule.engine],depth=Scan.Depth.QUICK,config={'target':authorization.target_snapshot},initiated_by_id=schedule.created_by_id)
    result=task.delay(str(scan.id)); schedule.last_run=timezone.now(); schedule.next_run=timezone.now()+timedelta(minutes=schedule.interval_minutes); schedule.save(update_fields=['last_run','next_run']); return {'status':'queued','scan_id':str(scan.id),'task_id':result.id}

@shared_task(name='enterprise.dispatch_due_schedules')
def dispatch_due_schedules():
    now=timezone.now(); reports=list(ReportSchedule.objects.filter(enabled=True,next_run__lte=now)); assurances=list(ContinuousAssuranceSchedule.objects.filter(enabled=True,next_run__lte=now)); queued=0
    for schedule in reports: execute_report_schedule.delay(str(schedule.id)); queued+=1
    for schedule in assurances: run_continuous_assurance.delay(str(schedule.id)); queued+=1
    return {'queued':queued,'reports':len(reports),'assurance':len(assurances)}

@shared_task(name='enterprise.cloud_discovery')
def cloud_discovery_task(run_id: str):
    run=CloudDiscoveryRun.objects.get(pk=run_id); run.status=CloudDiscoveryRun.Status.RUNNING; run.started_at=timezone.now(); run.save(update_fields=['status','started_at'])
    try:
        if run.provider=='aws':
            import boto3; resources=boto3.client('resourcegroupstaggingapi',region_name=(run.config or {}).get('region')).get_resources().get('ResourceTagMappingList',[])
        elif run.provider=='azure':
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
            subscription_id=(run.config or {}).get('subscription_id')
            if not subscription_id: raise ValueError('Azure discovery requires subscription_id')
            resources=[{'id':r.id,'name':r.name,'type':r.type} for r in ResourceManagementClient(DefaultAzureCredential(),subscription_id).resources.list()]
        elif run.provider=='gcp':
            from google.cloud import asset_v1
            scope=(run.config or {}).get('scope')
            if not scope: raise ValueError('GCP discovery requires scope')
            resources=[{'name':x.name,'asset_type':x.asset_type} for x in asset_v1.AssetServiceClient().search_all_resources(request={'scope':scope})]
        else: raise ValueError(f'Unsupported cloud provider: {run.provider}')
        run.resources=resources; run.status=CloudDiscoveryRun.Status.COMPLETED; run.completed_at=timezone.now(); run.save(update_fields=['resources','status','completed_at']); return {'status':'completed','run_id':run_id,'resources':len(resources)}
    except Exception as exc:
        run.status=CloudDiscoveryRun.Status.FAILED; run.error_message=str(exc); run.completed_at=timezone.now(); run.save(update_fields=['status','error_message','completed_at']); raise

@shared_task(name='enterprise.ingest_sbom')
def ingest_sbom_task(project_id:str,organization_id:str,source:str,source_ref:str,document:dict,user_id:str):
    from .models import Organization
    artifact=ingest_sbom(Project.objects.get(pk=project_id),Organization.objects.get(pk=organization_id),source,source_ref,document,user_id); return {'artifact_id':str(artifact.id),'component_count':artifact.component_count}
