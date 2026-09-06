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
from django_project.audit.models import DataExport
from django_project.vulnerabilities.models import Vulnerability
from .models import ContinuousAssuranceExecution, ContinuousAssuranceSchedule, Notification, OrganizationMembership, ReportRecipientDelivery, ReportSchedule, ReportScheduleExecution, CloudDiscoveryRun, ExternalIntegration, TenantProject
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
        if report.artifact_sha256 and artifact_sha256 != report.artifact_sha256:
            raise ValueError('Scheduled report artifact integrity verification failed')
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

@shared_task(name='enterprise.expire_report_exports')
def expire_report_exports(limit: int = 500):
    """Remove expired report artifacts while preserving their durable database provenance."""
    bounded_limit=max(1,min(limit,2000)); now=timezone.now()
    ids=list(DataExport.objects.filter(
        resource_type='project_report',expires_at__lte=now,
    ).exclude(status=DataExport.Status.EXPIRED).order_by('expires_at').values_list('id',flat=True)[:bounded_limit])
    expired=[]; failed=[]
    for report_id in ids:
        try:
            with transaction.atomic():
                report=DataExport.objects.select_for_update().get(pk=report_id)
                if report.status==DataExport.Status.EXPIRED or report.expires_at>timezone.now(): continue
                if report.file:
                    report.file.delete(save=False)
                report.file=None; report.status=DataExport.Status.EXPIRED; report.error_message=''
                report.save(update_fields=['file','status','error_message'])
                expired.append(str(report.id))
        except Exception as exc:
            DataExport.objects.filter(pk=report_id).exclude(status=DataExport.Status.EXPIRED).update(error_message=f'Artifact expiration failed: {exc}')
            failed.append({'report_id':str(report_id),'error':str(exc)})
    return {'expired':len(expired),'expired_ids':expired,'failed':failed}

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
def run_continuous_assurance(execution_id: str):
    from django_project.scans.models import Scan
    from fastapi_app.tasks.security_scan import run_nmap_scan,run_nuclei_scan
    from fastapi_app.tasks.advanced_scans import run_masscan_scan,run_semgrep_scan
    task_map={'nmap':run_nmap_scan,'nuclei':run_nuclei_scan,'masscan':run_masscan_scan,'semgrep':run_semgrep_scan}
    now=timezone.now()
    with transaction.atomic():
        execution=(ContinuousAssuranceExecution.objects.select_for_update().select_related(
            'schedule__project','schedule__organization','schedule__asset','schedule__authorization_decision','scan',
        ).get(pk=execution_id))
        schedule=execution.schedule
        if execution.status==ContinuousAssuranceExecution.Status.COMPLETED and execution.scan_id:
            return {'status':'completed','execution_id':str(execution.id),'scan_id':str(execution.scan_id),'task_id':execution.scanner_task_id,'replayed':True}
        if execution.status==ContinuousAssuranceExecution.Status.FAILED and execution.scan_id and execution.scan.is_finished:
            return {'status':'failed','execution_id':str(execution.id),'scan_id':str(execution.scan_id),'reason':execution.reason,'replayed':True}
        if execution.status==ContinuousAssuranceExecution.Status.QUEUED and execution.scan_id:
            return {'status':'queued','execution_id':str(execution.id),'scan_id':str(execution.scan_id),'task_id':execution.scanner_task_id,'replayed':True}
        if execution.status==ContinuousAssuranceExecution.Status.BLOCKED:
            return {'status':'blocked','execution_id':str(execution.id),'reason':execution.reason,'replayed':True}
        execution.status=ContinuousAssuranceExecution.Status.RUNNING
        execution.attempts+=1
        execution.started_at=execution.started_at or now
        execution.reason=''
        execution.save(update_fields=['status','attempts','started_at','reason','updated_at'])

        reason=''
        if not schedule.enabled:
            reason=schedule.disabled_reason or 'Continuous assurance schedule is disabled.'
        elif not schedule.organization.is_active:
            reason='Continuous assurance organization is inactive.'
        elif not TenantProject.objects.filter(project_id=schedule.project_id,organization_id=schedule.organization_id).exists():
            reason='Continuous assurance tenant binding no longer matches the project.'
        elif schedule.project.status != schedule.project.Status.ACTIVE:
            reason='Continuous assurance project is not active.'
        elif not (schedule.project.owner_id==schedule.created_by_id or schedule.project.memberships.filter(user_id=schedule.created_by_id).exists()):
            reason='Continuous assurance creator no longer has project access.'
        elif not OrganizationMembership.objects.filter(organization_id=schedule.organization_id,user_id=schedule.created_by_id,is_active=True).exists():
            reason='Continuous assurance creator no longer has active organization membership.'
        elif execution.organization_id != schedule.organization_id or execution.project_id != schedule.project_id:
            reason='Continuous assurance execution tenant lineage does not match its schedule.'
        elif execution.asset_id != schedule.asset_id or execution.authorization_decision_id != schedule.authorization_decision_id:
            reason='Continuous assurance execution authorization lineage does not match its schedule.'
        elif not schedule.asset or not schedule.asset.is_active or schedule.asset.project_id != schedule.project_id:
            reason='Continuous assurance requires its persisted active project asset binding.'
        if not reason:
            from fastapi_app.services.continuous_assurance import validate_assurance_engine_contract
            reason=validate_assurance_engine_contract(schedule.asset,schedule.scan_type,schedule.engine)

        authorization=None
        if not reason:
            from fastapi_app.services.authorization_guard import current_asset_authorization
            authorization,reason=current_asset_authorization(schedule.asset)
            if authorization is not None and authorization.id != schedule.authorization_decision_id:
                reason='Continuous assurance authorization was superseded; renew the schedule binding.'
        task=task_map.get(schedule.engine)
        if not reason and task is None:
            reason=f'Unsupported assurance engine: {schedule.engine}'
        if reason:
            execution.status=ContinuousAssuranceExecution.Status.BLOCKED
            execution.reason=reason
            execution.completed_at=now
            execution.save(update_fields=['status','reason','completed_at','updated_at'])
            schedule.enabled=False
            schedule.disabled_at=now
            schedule.disabled_reason=reason
            schedule.save(update_fields=['enabled','disabled_at','disabled_reason'])
            return {'status':'blocked','execution_id':str(execution.id),'reason':reason,'replayed':False}

        scan=execution.scan
        if scan is None:
            scan=Scan.objects.create(
                project=schedule.project,name=f'Continuous assurance {schedule.engine}',scan_type=schedule.scan_type,
                asset=schedule.asset,authorization_decision=authorization,engines=[schedule.engine],depth=Scan.Depth.QUICK,
                config={'target':authorization.target_snapshot,'assurance_execution_id':str(execution.id)},initiated_by_id=schedule.created_by_id,
            )
            execution.scan=scan
            execution.save(update_fields=['scan','updated_at'])
        schedule.last_run=now
        schedule.save(update_fields=['last_run'])

    try:
        result=task.delay(str(scan.id))
    except Exception as exc:
        with transaction.atomic():
            failed=ContinuousAssuranceExecution.objects.select_for_update().get(pk=execution_id)
            failed.status=ContinuousAssuranceExecution.Status.FAILED
            failed.reason=f'Scanner enqueue failed: {exc}'
            failed.completed_at=timezone.now()
            failed.save(update_fields=['status','reason','completed_at','updated_at'])
            Scan.objects.filter(pk=scan.id,status__in=[Scan.Status.PENDING,Scan.Status.QUEUED,Scan.Status.RUNNING]).update(status=Scan.Status.FAILED,error_message=failed.reason,completed_at=failed.completed_at)
        raise
    ContinuousAssuranceExecution.objects.filter(pk=execution_id,status=ContinuousAssuranceExecution.Status.RUNNING).update(status=ContinuousAssuranceExecution.Status.QUEUED,scanner_task_id=result.id)
    return {'status':'queued','execution_id':str(execution.id),'scan_id':str(scan.id),'task_id':result.id,'replayed':False}


def claim_continuous_assurance_execution(schedule_id: str, scheduled_for=None, *, advance_schedule: bool=False):
    """Claim one intended occurrence and snapshot every authority-bearing relation."""
    now=timezone.now()
    with transaction.atomic():
        schedule=ContinuousAssuranceSchedule.objects.select_for_update().get(pk=schedule_id)
        if advance_schedule and (not schedule.enabled or schedule.next_run > now):
            return None,False
        if not schedule.asset_id or not schedule.authorization_decision_id:
            reason='Continuous assurance schedule has no durable asset authorization binding.'
            schedule.enabled=False; schedule.disabled_at=now; schedule.disabled_reason=reason
            schedule.save(update_fields=['enabled','disabled_at','disabled_reason'])
            return None,False
        intended_for=schedule.next_run if advance_schedule else (scheduled_for or now)
        execution,created=ContinuousAssuranceExecution.objects.get_or_create(
            schedule=schedule,scheduled_for=intended_for,
            defaults={'organization_id':schedule.organization_id,'project_id':schedule.project_id,'asset_id':schedule.asset_id,'authorization_decision_id':schedule.authorization_decision_id},
        )
        if advance_schedule:
            next_run=schedule.next_run
            step=timedelta(minutes=schedule.interval_minutes)
            while next_run <= now:
                next_run += step
            schedule.next_run=next_run
            schedule.save(update_fields=['next_run'])
        return execution,created

@shared_task(name='enterprise.dispatch_due_schedules')
def dispatch_due_schedules():
    now=timezone.now(); execution_ids=[]; malformed=[]
    # Report schedules have one durable django-celery-beat PeriodicTask each.
    # Dispatching them here as well would enqueue the same report twice.
    schedule_ids=list(ContinuousAssuranceSchedule.objects.filter(enabled=True,next_run__lte=now).values_list('id',flat=True))
    for schedule_id in schedule_ids:
        execution,created=claim_continuous_assurance_execution(schedule_id,advance_schedule=True)
        if execution is None:
            if ContinuousAssuranceSchedule.objects.filter(pk=schedule_id,enabled=False,disabled_reason__gt='').exists():
                malformed.append(str(schedule_id))
            continue
        if created or (execution.status==ContinuousAssuranceExecution.Status.FAILED and not execution.scan_id):
            execution_ids.append(str(execution.id))
    queued=0
    for execution_id in execution_ids:
        try:
            result=run_continuous_assurance.delay(execution_id)
            ContinuousAssuranceExecution.objects.filter(pk=execution_id).update(celery_task_id=result.id)
            queued+=1
        except Exception as exc:
            with transaction.atomic():
                failed=ContinuousAssuranceExecution.objects.select_for_update().select_related('schedule').get(pk=execution_id)
                failed.status=ContinuousAssuranceExecution.Status.FAILED
                failed.reason=f'Assurance worker enqueue failed: {exc}'
                failed.completed_at=timezone.now()
                failed.save(update_fields=['status','reason','completed_at','updated_at'])
                if failed.schedule.enabled and failed.schedule.next_run > failed.scheduled_for:
                    failed.schedule.next_run=failed.scheduled_for
                    failed.schedule.save(update_fields=['next_run'])
    result={'queued':queued,'reports':0,'assurance':len(execution_ids)}
    if malformed: result['malformed']=malformed
    return result

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
