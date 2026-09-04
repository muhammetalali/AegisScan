from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.authorization_guard import authorization_snapshot, require_bound_scan_authorization, revalidate_bound_authorization
from fastapi_app.services.evidence_identity import evidence_id
from fastapi_app.services.scanner_adapters import run_masscan, run_semgrep, validate_code_target


def _ensure_engine(name: str, display_name: str, category: str, timeout: int) -> ScanEngine:
    engine, _ = ScanEngine.objects.get_or_create(name=name, defaults={'display_name': display_name, 'description': f'{display_name} scanner engine', 'category': category, 'version': '1.0.0', 'status': ScanEngine.EngineStatus.ACTIVE, 'is_core': True, 'timeout': timeout})
    return engine


def _execution(scan: Scan, engine: ScanEngine) -> ScanEngineExecution:
    item, _ = ScanEngineExecution.objects.get_or_create(scan=scan, engine=engine, defaults={'status': ScanEngineExecution.ExecutionStatus.PENDING})
    item.status=ScanEngineExecution.ExecutionStatus.RUNNING; item.progress=10; item.started_at=datetime.now(timezone.utc); item.completed_at=None; item.error_message=''; item.logs=''
    item.save(update_fields=['status','progress','started_at','completed_at','error_message','logs','updated_at'])
    return item


def _completed_delivery(scan: Scan, engine: ScanEngine) -> dict[str, Any] | None:
    execution = ScanEngineExecution.objects.filter(scan=scan, engine=engine).first()
    if not execution or execution.status != ScanEngineExecution.ExecutionStatus.COMPLETED or scan.status != Scan.Status.COMPLETED:
        return None
    result = execution.result_data if isinstance(execution.result_data, dict) else {}
    return {'status': scan.status, 'scan_id': str(scan.id), 'tool': engine.name, 'target': result.get('target') or result.get('source'), 'finding_ids': result.get('finding_ids', []), 'redelivered': True}


def _finish_failed(scan: Scan, execution: ScanEngineExecution, message: str, context: dict[str, Any] | None = None):
    now=datetime.now(timezone.utc); execution.status=ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=now; execution.error_message=message; execution.save(update_fields=['status','progress','completed_at','error_message','updated_at']); ScanLog.objects.create(scan=scan,engine_execution=execution,level=ScanLog.Level.ERROR,message='advanced scanner execution failed',context={'error':message,**(context or {})}); scan.status=Scan.Status.FAILED; scan.error_message=message; scan.completed_at=now; scan.progress=100; scan.save(update_fields=['status','error_message','completed_at','progress','updated_at']); return {'status':'failed','scan_id':str(scan.id),'error':message}


def _masscan_findings(raw: str) -> list[dict[str, Any]]:
    records=json.loads(raw) if raw.strip() else []
    if isinstance(records,dict): records=[records]
    out=[]
    for record in records:
        if not isinstance(record,dict): continue
        ip=str(record.get('ip') or '').strip()
        for port in record.get('ports',[]) if isinstance(record.get('ports'),list) else []:
            if not isinstance(port,dict): continue
            try: port_no=int(port.get('port'))
            except (TypeError,ValueError): continue
            protocol=str(port.get('proto') or port.get('protocol') or 'tcp').lower(); out.append({'ip':ip,'port':port_no,'protocol':protocol,'record':record})
    return out


def _semgrep_findings(raw: str) -> list[dict[str, Any]]:
    data=json.loads(raw) if raw.strip() else {}; results=data.get('results',[]) if isinstance(data,dict) else []; findings=[]
    for item in results:
        if not isinstance(item,dict): continue
        extra=item.get('extra') if isinstance(item.get('extra'),dict) else {}; message=str(extra.get('message') or item.get('check_id') or 'Semgrep finding'); severity=str(extra.get('severity') or 'WARNING').lower(); sev={'error':Vulnerability.Severity.HIGH,'warning':Vulnerability.Severity.MEDIUM,'info':Vulnerability.Severity.INFO}.get(severity,Vulnerability.Severity.MEDIUM); path=str(item.get('path') or ''); start=item.get('start') if isinstance(item.get('start'),dict) else {}
        findings.append({'check_id':str(item.get('check_id') or ''),'message':message,'severity':sev,'path':path,'line':int(start.get('line') or 0),'record':item})
    return findings


def _git_checkout(asset_config:dict[str,Any]):
    repo_url=str(asset_config.get('repo_url') or '').strip()
    if not repo_url.startswith(('https://','ssh://','git@')): raise ValueError('Semgrep repository asset requires a git repository URL')
    holder=tempfile.TemporaryDirectory(prefix='aegis-semgrep-'); destination=Path(holder.name)/'repo'; branch=str(asset_config.get('branch') or '').strip(); token_env=str(asset_config.get('token_env') or '').strip(); env=os.environ.copy()
    if token_env and env.get(token_env):
        token=env[token_env]
        if repo_url.startswith('https://') and '@' not in repo_url.split('://',1)[1].split('/',1)[0]: repo_url='https://oauth2:%s@%s' % (token,repo_url.split('://',1)[1])
    command=['git','clone','--depth','1'];
    if branch: command+=['--branch',branch]
    command += [repo_url,str(destination)]; result=subprocess.run(command,capture_output=True,text=True,timeout=300,check=False,env=env)
    if result.returncode!=0: holder.cleanup(); raise RuntimeError(result.stderr.strip() or 'git clone failed')
    return str(destination),holder


@shared_task(bind=True,name='fastapi_app.tasks.advanced_scans.run_masscan_scan',max_retries=1,default_retry_delay=30)
def run_masscan_scan(self,scan_id:str)->dict[str,Any]:
    scan,target,authorization=require_bound_scan_authorization(scan_id)
    if scan is None: return _finish_failed(Scan.objects.get(pk=scan_id), _execution(Scan.objects.get(pk=scan_id), _ensure_engine('masscan','Masscan',ScanEngine.EngineCategory.RECON,300)), target)
    if scan.scan_type != Scan.Type.NETWORK: return _finish_failed(scan, _execution(scan,_ensure_engine('masscan','Masscan',ScanEngine.EngineCategory.RECON,300)), 'Execution blocked: Masscan requires a network scan type.')
    engine=_ensure_engine('masscan','Masscan',ScanEngine.EngineCategory.RECON,300); completed=_completed_delivery(scan,engine)
    if completed: return completed
    execution=_execution(scan,engine); execution.result_data=authorization_snapshot(authorization); execution.save(update_fields=['result_data','updated_at'])
    try:
        result=run_masscan(str(target),ports=str((scan.config or {}).get('ports') or '1-65535'),rate=int((scan.config or {}).get('rate') or 1000),timeout=300); observations=_masscan_findings(result.stdout); ok,reason=revalidate_bound_authorization(scan,authorization)
        if not ok: return _finish_failed(scan,execution,reason,authorization_snapshot(authorization))
        now=datetime.now(timezone.utc)
        with transaction.atomic():
            scanner_evidence,_=Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'masscan','scanner_output'),defaults={'scan':scan,'asset':scan.asset,'source':'masscan','evidence_type':'scanner_output','raw_output':result.stdout,'metadata':{'stderr':result.stderr,'exit_code':result.exit_code,'target':result.target,'format':'json',**authorization_snapshot(authorization)},'collected_by':scan.initiated_by}); findings=[]
            for obs in observations:
                finding=Vulnerability.objects.filter(scan=scan,asset=scan.asset,source_engine='masscan',raw_data__port=obs['port'],raw_data__protocol=obs['protocol'],raw_data__ip=obs['ip']).first()
                if finding is None: finding=Vulnerability.objects.create(scan=scan,project=scan.project,asset=scan.asset,title=f"Open {obs['protocol'].upper()} port {obs['port']}",description=f"Masscan detected an open {obs['protocol'].upper()} port {obs['port']} on {obs['ip'] or target}.",severity=Vulnerability.Severity.INFO,status=Vulnerability.Status.OPEN,confidence=Vulnerability.Confidence.HIGH,category='network',tags=['masscan',obs['protocol']],risk_score=10.0,validation_status='unverified',source_engine='masscan',raw_data={**obs['record'],'observation_ip':obs['ip'],'observation_port':obs['port'],'observation_protocol':obs['protocol']})
                Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'masscan','scanner_output',str(finding.id)),defaults={'scan':scan,'asset':scan.asset,'finding':finding,'source':'masscan','evidence_type':'scanner_output','raw_output':scanner_evidence.raw_output,'metadata':{'scanner_evidence_id':str(scanner_evidence.id),'observation_ip':obs['ip'],'observation_port':obs['port'],'observation_protocol':obs['protocol'],**authorization_snapshot(authorization)},'collected_by':scan.initiated_by}); finding.evidence_count=finding.evidence_records.count(); finding.save(update_fields=['evidence_count','updated_at']); findings.append(finding)
            execution.status=ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code==0 else ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=now; execution.findings_found=len(findings); execution.evidences_collected=1; execution.result_data={'tool':'masscan','target':result.target,'exit_code':result.exit_code,'finding_ids':[str(v.id) for v in findings],'scanner_evidence_id':str(scanner_evidence.id),**authorization_snapshot(authorization)}; execution.save(update_fields=['status','progress','completed_at','findings_found','evidences_collected','result_data','updated_at']); scan.status=Scan.Status.COMPLETED if result.exit_code==0 else Scan.Status.PARTIAL; scan.progress=100; scan.completed_at=now; scan.findings_count=len(findings); scan.engine_results={**(scan.engine_results or {}),'masscan':execution.result_data}; scan.save(update_fields=['status','progress','completed_at','findings_count','engine_results','updated_at'])
        return {'status':scan.status,'scan_id':scan_id,'tool':'masscan','target':result.target,'finding_ids':[str(v.id) for v in findings],**authorization_snapshot(authorization)}
    except Exception as exc:
        if self.request.retries < self.max_retries: raise self.retry(exc=exc)
        return _finish_failed(scan,execution,str(exc),authorization_snapshot(authorization))


@shared_task(bind=True,name='fastapi_app.tasks.advanced_scans.run_semgrep_scan',max_retries=1,default_retry_delay=30)
def run_semgrep_scan(self,scan_id:str)->dict[str,Any]:
    scan=Scan.objects.select_related('asset','initiated_by','project').get(pk=scan_id)
    if not scan.asset: raise ValueError('A scan must reference an asset before execution')
    config=scan.asset.configuration or {}; engine=_ensure_engine('semgrep','Semgrep',ScanEngine.EngineCategory.ANALYSIS,900); completed=_completed_delivery(scan,engine)
    if completed: return completed
    execution=_execution(scan,engine)
    if config.get('authorized') is not True: return _finish_failed(scan,execution,'Execution blocked: asset is not explicitly marked authorized.')
    holder=None
    try:
        if config.get('repo_url'): source,holder=_git_checkout(config)
        else: source=validate_code_target(str(config.get('path') or scan.config.get('path') or ''))
        result=run_semgrep(source,timeout=900); observations=_semgrep_findings(result.stdout); now=datetime.now(timezone.utc)
        with transaction.atomic():
            scanner_evidence,_=Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'semgrep','scanner_output'),defaults={'scan':scan,'asset':scan.asset,'source':'semgrep','evidence_type':'scanner_output','raw_output':result.stdout,'metadata':{'stderr':result.stderr,'exit_code':result.exit_code,'source':source,'format':'json'},'collected_by':scan.initiated_by}); findings=[]
            for obs in observations:
                finding=Vulnerability.objects.filter(scan=scan,asset=scan.asset,source_engine='semgrep',file_path=obs['path'],line_start=obs['line'],title=obs['message'][:300]).first()
                if finding is None: finding=Vulnerability.objects.create(scan=scan,project=scan.project,asset=scan.asset,title=obs['message'][:300],description=obs['message'],severity=obs['severity'],status=Vulnerability.Status.OPEN,confidence=Vulnerability.Confidence.HIGH,category='code',file_path=obs['path'][:500],line_start=max(0,obs['line']) or None,risk_score={Vulnerability.Severity.HIGH:80.0,Vulnerability.Severity.MEDIUM:60.0,Vulnerability.Severity.INFO:10.0}[obs['severity']],validation_status='unverified',source_engine='semgrep',raw_data=obs['record'])
                Evidence.objects.update_or_create(id=evidence_id('scan',scan_id,'semgrep','scanner_output',str(finding.id)),defaults={'scan':scan,'asset':scan.asset,'finding':finding,'source':'semgrep','evidence_type':'scanner_output','raw_output':scanner_evidence.raw_output,'metadata':{'scanner_evidence_id':str(scanner_evidence.id),'check_id':obs['check_id'],'path':obs['path'],'line':obs['line']},'collected_by':scan.initiated_by}); finding.evidence_count=finding.evidence_records.count(); finding.save(update_fields=['evidence_count','updated_at']); findings.append(finding)
            execution.status=ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code==0 else ScanEngineExecution.ExecutionStatus.FAILED; execution.progress=100; execution.completed_at=now; execution.findings_found=len(findings); execution.evidences_collected=1; execution.result_data={'tool':'semgrep','source':source,'exit_code':result.exit_code,'finding_ids':[str(v.id) for v in findings],'scanner_evidence_id':str(scanner_evidence.id)}; execution.save(update_fields=['status','progress','completed_at','findings_found','evidences_collected','result_data','updated_at']); scan.status=Scan.Status.COMPLETED if result.exit_code==0 else Scan.Status.PARTIAL; scan.progress=100; scan.completed_at=now; scan.findings_count=len(findings); scan.engine_results={**(scan.engine_results or {}),'semgrep':execution.result_data}; scan.save(update_fields=['status','progress','completed_at','findings_count','engine_results','updated_at'])
        return {'status':scan.status,'scan_id':scan_id,'tool':'semgrep','finding_ids':[str(v.id) for v in findings]}
    except Exception as exc:
        if self.request.retries < self.max_retries: raise self.retry(exc=exc)
        return _finish_failed(scan,execution,str(exc))
    finally:
        if holder: holder.cleanup()
