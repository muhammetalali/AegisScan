from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.scope_authorization import is_target_authorized
from fastapi_app.services.evidence_identity import evidence_id
from fastapi_app.services.nmap_parser import parse_nmap_xml
from fastapi_app.services.scanner_adapters import run_nuclei
from fastapi_app.services.tool_abstraction import ToolRequest, get_tool
from fastapi_app.services.nmap_finding_ingestion import ingest_nmap_findings


def _ensure_engine(name: str, display_name: str, category: str, timeout: int) -> ScanEngine:
    engine, _ = ScanEngine.objects.get_or_create(name=name, defaults={'display_name': display_name, 'description': f'{display_name} scanner engine', 'category': category, 'version': '1.0.0', 'status': ScanEngine.EngineStatus.ACTIVE, 'is_core': True, 'timeout': timeout})
    return engine


def _start_execution(scan: Scan, engine: ScanEngine) -> ScanEngineExecution:
    now = datetime.now(timezone.utc)
    execution, _ = ScanEngineExecution.objects.get_or_create(scan=scan, engine=engine, defaults={'status': ScanEngineExecution.ExecutionStatus.PENDING})
    execution.status=ScanEngineExecution.ExecutionStatus.RUNNING; execution.progress=10; execution.started_at=now; execution.completed_at=None; execution.duration=0; execution.findings_found=0; execution.evidences_collected=0; execution.error_message=''; execution.logs=''
    execution.save(update_fields=['status','progress','started_at','completed_at','duration','findings_found','evidences_collected','error_message','logs','updated_at'])
    ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.INFO, message=f'{engine.name} execution started', context={'engine': engine.name})
    return execution


def _completed_delivery(scan: Scan, engine: ScanEngine) -> dict[str, Any] | None:
    execution = ScanEngineExecution.objects.filter(scan=scan, engine=engine).first()
    if not execution or execution.status != ScanEngineExecution.ExecutionStatus.COMPLETED:
        return None
    if scan.status != Scan.Status.COMPLETED:
        return None
    result = execution.result_data if isinstance(execution.result_data, dict) else {}
    return {
        'status': scan.status,
        'scan_id': str(scan.id),
        'tool': engine.name,
        'target': result.get('target'),
        'finding_ids': result.get('finding_ids', []),
        'redelivered': True,
    }


def _first_string(value: Any) -> str:
    if isinstance(value, str): return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip(): return item.strip()
    return ''


def _severity(value: Any) -> str:
    normalized = _first_string(value).lower()
    return normalized if normalized in set(Vulnerability.Severity.values) else Vulnerability.Severity.INFO


def _risk_score(severity: str) -> float:
    return {Vulnerability.Severity.CRITICAL:95.0,Vulnerability.Severity.HIGH:80.0,Vulnerability.Severity.MEDIUM:60.0,Vulnerability.Severity.LOW:35.0,Vulnerability.Severity.INFO:10.0}[severity]


def _parse_nuclei_findings(raw_output: str) -> list[dict[str, Any]]:
    findings=[]
    for line in raw_output.splitlines():
        line=line.strip()
        if not line: continue
        try: record=json.loads(line)
        except json.JSONDecodeError: continue
        if not isinstance(record,dict): continue
        info=record.get('info') if isinstance(record.get('info'),dict) else {}; classification=info.get('classification') if isinstance(info.get('classification'),dict) else {}
        cve_ids=classification.get('cve-id') if isinstance(classification.get('cve-id'),list) else []; cwe_ids=classification.get('cwe-id') if isinstance(classification.get('cwe-id'),list) else []
        matched_at=_first_string(record.get('matched-at')) or _first_string(record.get('host'))
        findings.append({'record':record,'title':_first_string(info.get('name')) or _first_string(record.get('template-id')) or 'Nuclei finding','description':_first_string(info.get('description')) or 'Finding reported by Nuclei.','remediation':_first_string(info.get('remediation')),'severity':_severity(info.get('severity')),'references':info.get('reference') if isinstance(info.get('reference'),list) else [],'cve_ids':[str(x) for x in cve_ids if str(x).strip()],'cwe_id':_first_string(cwe_ids),'url':matched_at,'method':_first_string(record.get('type')).upper(),'template_id':_first_string(record.get('template-id')),'matcher_name':_first_string(record.get('matcher-name'))})
    return findings


def _ingest_nuclei_findings(scan: Scan, evidence: Evidence, raw_output: str) -> list[Vulnerability]:
    findings=[]
    for item in _parse_nuclei_findings(raw_output):
        vulnerability=Vulnerability.objects.filter(scan=scan,asset=scan.asset,source_engine='nuclei',title=item['title'],url=item['url'][:500]).first()
        if vulnerability is None:
            vulnerability=Vulnerability.objects.create(scan=scan,project=scan.project,asset=scan.asset,title=item['title'],description=item['description'],severity=item['severity'],status=Vulnerability.Status.OPEN,confidence=Vulnerability.Confidence.HIGH,category='web',cwe_id=item['cwe_id'],cve_ids=item['cve_ids'],tags=[x for x in [item['template_id'],item['matcher_name']] if x],url=item['url'][:500],method=item['method'][:10],risk_score=_risk_score(item['severity']),evidence_count=0,verified_evidence_count=0,validation_status='unverified',remediation=item['remediation'],references=item['references'],source_engine='nuclei',raw_data=item['record'])
        else:
            vulnerability.last_seen=datetime.now(timezone.utc); vulnerability.raw_data=item['record']; vulnerability.save(update_fields=['last_seen','raw_data','updated_at'])
        if evidence.finding_id in {None, vulnerability.id}: evidence.finding=vulnerability; evidence.save(update_fields=['finding'])
        else: Evidence.objects.update_or_create(id=evidence_id('scan',str(scan.id),'nuclei','scanner_output',str(vulnerability.id)),defaults={'scan':scan,'asset':scan.asset,'finding':vulnerability,'source':'nuclei','evidence_type':'scanner_output','raw_output':evidence.raw_output,'metadata':{**(evidence.metadata or {}),'finding_id':str(vulnerability.id)}})
        vulnerability.evidence_count=vulnerability.evidence_records.count(); vulnerability.save(update_fields=['evidence_count','updated_at']); findings.append(vulnerability)
    return findings


def _fail_scan(scan: Scan, execution: ScanEngineExecution, message: str) -> dict[str, Any]:
    now=datetime.now(timezone.utc); execution.status=ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=now; execution.error_message=message; execution.save(update_fields=['status','progress','completed_at','error_message','updated_at']); ScanLog.objects.create(scan=scan,engine_execution=execution,level=ScanLog.Level.ERROR,message='scanner execution failed',context={'error':message}); scan.status=Scan.Status.FAILED; scan.error_message=message; scan.completed_at=now; scan.save(update_fields=['status','error_message','completed_at','updated_at']); return {'status':'failed','scan_id':str(scan.id),'error':message}


@shared_task(bind=True,name='fastapi_app.tasks.security_scan.run_nmap_scan',max_retries=1,default_retry_delay=30)
def run_nmap_scan(self,scan_id:str)->dict[str,Any]:
    scan=Scan.objects.select_related('asset','initiated_by','project').get(pk=scan_id)
    if not scan.asset: raise ValueError('A scan must reference an asset before execution')
    configuration=scan.asset.configuration or {}
    engine=_ensure_engine('nmap','Nmap',ScanEngine.EngineCategory.RECON,300)
    completed = _completed_delivery(scan, engine)
    if completed: return completed
    if configuration.get('authorized') is not True: return _fail_scan(scan,_start_execution(scan,engine),'Execution blocked: asset is not explicitly marked authorized.')
    target=configuration.get('host') or configuration.get('ip') or configuration.get('domain') or configuration.get('url')
    if not target: raise ValueError('Authorized asset has no host/ip/domain/url target')
    if not is_target_authorized(target): return _fail_scan(scan,_start_execution(scan,engine),'Execution blocked: target is outside the server-side authorized scan scope.')
    scan.status=Scan.Status.RUNNING; scan.started_at=datetime.now(timezone.utc); scan.current_phase='nmap'; scan.current_engine='nmap'; scan.progress=10; scan.save(update_fields=['status','started_at','current_phase','current_engine','progress','updated_at'])
    execution=_start_execution(scan,engine)
    try:
        result=get_tool('nmap').run(ToolRequest(target=target,authorized=True),timeout=120 if scan.depth==Scan.Depth.QUICK else 300); parsed=parse_nmap_xml(result.stdout) if result.stdout.strip() else {'hosts':[],'host_count':0,'open_ports':0}; completed_at=datetime.now(timezone.utc)
        with transaction.atomic():
            evidence,_=Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'nmap','scanner_output'),defaults={'scan':scan,'asset':scan.asset,'source':result.tool,'evidence_type':'scanner_output','raw_output':result.stdout,'metadata':{'stderr':result.stderr,'exit_code':result.exit_code,'target':result.target,'parsed':parsed},'collected_by':scan.initiated_by}); findings=ingest_nmap_findings(scan,evidence,parsed); execution.status=ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code==0 else ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=completed_at; execution.findings_found=len(findings); execution.evidences_collected=1; execution.result_data={'tool':result.tool,'target':result.target,'exit_code':result.exit_code,'parsed':parsed,'evidence_id':str(evidence.id),'finding_ids':[str(v.id) for v in findings]}; execution.logs=result.stderr or ''; execution.save(update_fields=['status','progress','completed_at','findings_found','evidences_collected','result_data','logs','updated_at']); scan.status=Scan.Status.COMPLETED if result.exit_code==0 else Scan.Status.PARTIAL; scan.progress=100; scan.completed_at=completed_at; scan.findings_count=len(findings); scan.engine_results={**(scan.engine_results or {}),'nmap':execution.result_data}; scan.save(update_fields=['status','progress','completed_at','findings_count','engine_results','updated_at'])
        return {'status':scan.status,'scan_id':scan_id,'tool':'nmap','target':result.target,'finding_ids':[str(v.id) for v in findings]}
    except Exception as exc:
        if self.request.retries < self.max_retries: raise self.retry(exc=exc)
        return _fail_scan(scan,execution,str(exc))


@shared_task(bind=True,name='fastapi_app.tasks.security_scan.run_nuclei_scan',max_retries=1,default_retry_delay=30)
def run_nuclei_scan(self,scan_id:str)->dict[str,Any]:
    scan=Scan.objects.select_related('asset','initiated_by','project').get(pk=scan_id)
    if not scan.asset: raise ValueError('A scan must reference an asset before execution')
    configuration=scan.asset.configuration or {}; target=configuration.get('url'); engine=_ensure_engine('nuclei','Nuclei',ScanEngine.EngineCategory.ANALYSIS,600); completed=_completed_delivery(scan,engine)
    if completed: return completed
    execution=_start_execution(scan,engine)
    if configuration.get('authorized') is not True: return _fail_scan(scan,execution,'Execution blocked: asset is not explicitly marked authorized.')
    if not target: return _fail_scan(scan,execution,'Nuclei requires an authorized http/https URL target')
    if not is_target_authorized(target): return _fail_scan(scan,execution,'Execution blocked: target is outside the server-side authorized scan scope.')
    scan.status=Scan.Status.RUNNING; scan.started_at=datetime.now(timezone.utc); scan.current_phase='nuclei'; scan.current_engine='nuclei'; scan.progress=10; scan.save(update_fields=['status','started_at','current_phase','current_engine','progress','updated_at'])
    try:
        result=run_nuclei(target,timeout=600); completed_at=datetime.now(timezone.utc)
        with transaction.atomic():
            evidence,_=Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'nuclei','scanner_output'),defaults={'scan':scan,'asset':scan.asset,'source':result.tool,'evidence_type':'scanner_output','raw_output':result.stdout,'metadata':{'stderr':result.stderr,'exit_code':result.exit_code,'target':result.target,'format':'jsonl'},'collected_by':scan.initiated_by}); findings=_ingest_nuclei_findings(scan,evidence,result.stdout); execution.status=ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code==0 else ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=completed_at; execution.findings_found=len(findings); execution.evidences_collected=1; execution.result_data={'tool':result.tool,'target':result.target,'exit_code':result.exit_code,'result_count':len(findings),'evidence_id':str(evidence.id),'finding_ids':[str(v.id) for v in findings]}; execution.logs=result.stderr or ''; execution.save(update_fields=['status','progress','completed_at','findings_found','evidences_collected','result_data','logs','updated_at']); scan.status=Scan.Status.COMPLETED if result.exit_code==0 else Scan.Status.PARTIAL; scan.progress=100; scan.completed_at=completed_at; scan.engine_results={**(scan.engine_results or {}),'nuclei':execution.result_data}; scan.save(update_fields=['status','progress','completed_at','engine_results','updated_at'])
        return {'status':scan.status,'scan_id':scan_id,'tool':'nuclei','target':result.target,'finding_ids':[str(v.id) for v in findings]}
    except Exception as exc:
        if self.request.retries < self.max_retries: raise self.retry(exc=exc)
        return _fail_scan(scan,execution,str(exc))
