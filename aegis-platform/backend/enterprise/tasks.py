from __future__ import annotations

import json
import hashlib
from datetime import timedelta

from asgiref.sync import async_to_sync
from celery import shared_task
from django.core.mail import EmailMessage, send_mail
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from .models import ContinuousAssuranceSchedule, Notification, ReportRecipientDelivery, ReportSchedule, ReportScheduleExecution, CloudDiscoveryRun, ExternalIntegration
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

@shared_task(bind=True,name='enterprise.execute_report_schedule')
def execute_report_schedule(self, schedule_id: str, delivery_id: str | None = None):
    from fastapi_app.routers.reports import ReportCreate, _build_payload, _create_report
    task_delivery_id=delivery_id or getattr(self.request,'id',None)
    if not task_delivery_id: raise ValueError('Scheduled report execution requires a durable Celery delivery identifier')
    redelivered=bool((getattr(self.request,'delivery_info',None) or {}).get('redelivered'))
    try:
        with transaction.atomic():
            schedule=ReportSchedule.objects.select_for_update().select_related('project').get(pk=schedule_id)
            if not schedule.enabled:return {'status':'disabled','schedule_id':schedule_id}
            execution,created=ReportScheduleExecution.objects.select_for_update().get_or_create(
                delivery_id=task_delivery_id,defaults={'schedule':schedule},
            )
            if execution.schedule_id != schedule.id: raise ValueError('Report delivery identifier is already bound to another schedule')
            if execution.status==ReportScheduleExecution.Status.COMPLETED and execution.report_id:
                return {'status':'completed','schedule_id':schedule_id,'report_id':str(execution.report_id),'replayed':True}
            if not created and execution.status==ReportScheduleExecution.Status.RUNNING and not redelivered:
                return {'status':'in_progress','schedule_id':schedule_id,'execution_id':str(execution.id)}
            execution.status=ReportScheduleExecution.Status.RUNNING; execution.attempts+=1; execution.started_at=timezone.now(); execution.error_message=''
            execution.save(update_fields=['status','attempts','started_at','error_message','updated_at'])
            payload=async_to_sync(_build_payload)(str(schedule.project_id),None,schedule.report_type)
            report=async_to_sync(_create_report)(ReportCreate(project_id=str(schedule.project_id),title=schedule.title,report_type=schedule.report_type,format=schedule.format),str(schedule.created_by_id),payload)
            now=timezone.now(); execution.report=report; execution.status=ReportScheduleExecution.Status.COMPLETED; execution.completed_at=now
            execution.save(update_fields=['report','status','completed_at','updated_at'])
            delivery_ids=[]
            for recipient in schedule.recipients:
                recipient_hash=hashlib.sha256(recipient.encode('utf-8')).hexdigest()[:16]
                delivery,_=ReportRecipientDelivery.objects.get_or_create(
                    execution=execution,recipient=recipient,
                    defaults={'message_id':f'<aegis-report-{execution.id}-{recipient_hash}@aegisscan.local>'},
                )
                delivery_ids.append(str(delivery.id))
            def queue_recipient_deliveries():
                for recipient_delivery_id in delivery_ids:
                    deliver_scheduled_report.delay(recipient_delivery_id)
            transaction.on_commit(queue_recipient_deliveries,robust=True)
            schedule.last_run=now; schedule.next_run=now+timedelta(minutes={'daily':1440,'weekly':10080,'monthly':43200}.get(schedule.frequency,60)); schedule.save(update_fields=['last_run','next_run','updated_at'])
        return {'status':'completed','schedule_id':schedule_id,'report_id':str(report.id),'execution_id':str(execution.id),'recipient_deliveries':len(delivery_ids),'replayed':False}
    except Exception as exc:
        with transaction.atomic():
            schedule=ReportSchedule.objects.get(pk=schedule_id)
            execution,_=ReportScheduleExecution.objects.select_for_update().get_or_create(
                delivery_id=task_delivery_id,defaults={'schedule':schedule},
            )
            if execution.schedule_id != schedule.id: raise ValueError('Report delivery identifier is already bound to another schedule') from exc
            if execution.status != ReportScheduleExecution.Status.COMPLETED:
                execution.status=ReportScheduleExecution.Status.FAILED; execution.attempts=max(1,execution.attempts); execution.error_message=str(exc)
                execution.save(update_fields=['status','attempts','error_message','updated_at'])
        raise

@shared_task(bind=True,name='enterprise.deliver_scheduled_report',autoretry_for=(Exception,),retry_backoff=True,max_retries=3)
def deliver_scheduled_report(self, recipient_delivery_id: str):
    redelivered=bool((getattr(self.request,'delivery_info',None) or {}).get('redelivered'))
    stale_before=timezone.now()-timedelta(minutes=10)
    with transaction.atomic():
        delivery=ReportRecipientDelivery.objects.select_for_update().select_related('execution__schedule','execution__report').get(pk=recipient_delivery_id)
        if delivery.status==ReportRecipientDelivery.Status.SENT:
            return {'status':'sent','delivery_id':recipient_delivery_id,'message_id':delivery.message_id,'artifact_sha256':delivery.artifact_sha256,'replayed':True}
        if delivery.status==ReportRecipientDelivery.Status.SENDING and delivery.updated_at>=stale_before and not redelivered:
            return {'status':'in_progress','delivery_id':recipient_delivery_id}
        delivery.status=ReportRecipientDelivery.Status.SENDING; delivery.attempts+=1; delivery.last_error=''
        delivery.save(update_fields=['status','attempts','last_error','updated_at'])
    try:
        report=delivery.execution.report
        if not report or report.status!='completed' or not report.file:
            raise ValueError('Recipient delivery requires a completed persisted report artifact')
        report.file.open('rb')
        try: content=report.file.read()
        finally: report.file.close()
        artifact_sha256=hashlib.sha256(content).hexdigest()
        content_type={'pdf':'application/pdf','json':'application/json','csv':'text/csv'}.get(report.format,'application/octet-stream')
        message=EmailMessage(
            subject=delivery.execution.schedule.title,
            body=f'AegisScan scheduled report {report.id} is attached. Delivery evidence: {delivery.id}.',
            to=[delivery.recipient],headers={'Message-ID':delivery.message_id},
        )
        message.attach(report.file.name.rsplit('/',1)[-1],content,content_type)
        if message.send(fail_silently=False)!=1: raise RuntimeError('Email backend did not accept the scheduled report message')
        now=timezone.now(); ReportRecipientDelivery.objects.filter(pk=delivery.pk).update(status=ReportRecipientDelivery.Status.SENT,sent_at=now,artifact_sha256=artifact_sha256,last_error='')
        return {'status':'sent','delivery_id':recipient_delivery_id,'message_id':delivery.message_id,'artifact_sha256':artifact_sha256,'replayed':False}
    except Exception as exc:
        ReportRecipientDelivery.objects.filter(pk=delivery.pk).update(status=ReportRecipientDelivery.Status.FAILED,last_error=str(exc))
        raise

@shared_task(name='enterprise.dispatch_report_deliveries')
def dispatch_report_deliveries(limit: int = 100):
    ids=list(ReportRecipientDelivery.objects.filter(
        Q(status__in=[ReportRecipientDelivery.Status.QUEUED,ReportRecipientDelivery.Status.FAILED]) |
        Q(status=ReportRecipientDelivery.Status.SENDING,updated_at__lt=timezone.now()-timedelta(minutes=10)),
        attempts__lt=4,
    ).order_by('created_at').values_list('id',flat=True)[:max(1,min(limit,500))])
    for delivery_id in ids: deliver_scheduled_report.delay(str(delivery_id))
    return {'queued':len(ids),'delivery_ids':[str(item) for item in ids]}

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
    now=timezone.now(); assurances=list(ContinuousAssuranceSchedule.objects.filter(enabled=True,next_run__lte=now)); queued=0
    # Report schedules have one durable django-celery-beat PeriodicTask each.
    # Dispatching them here as well would enqueue the same report twice.
    for schedule in assurances: run_continuous_assurance.delay(str(schedule.id)); queued+=1
    return {'queued':queued,'reports':0,'assurance':len(assurances)}

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
