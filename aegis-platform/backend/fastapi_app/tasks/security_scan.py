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

from django_project.evidence.models import Evidence, ValidationRun
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from django_project.vulnerabilities.models import Vulnerability
from ..services.scope_authorization import is_target_authorized
from ..services.nmap_parser import parse_nmap_xml
from ..services.tool_abstraction import ToolRequest, get_tool
from ..services.scanner_adapters import run_nuclei
from ..services.nmap_finding_ingestion import ingest_nmap_findings


def _ensure_engine(name: str, display_name: str, category: str, timeout: int) -> ScanEngine:
    engine, _ = ScanEngine.objects.get_or_create(
        name=name,
        defaults={
            'display_name': display_name,
            'description': f'{display_name} scanner engine',
            'category': category,
            'version': '1.0.0',
            'status': ScanEngine.EngineStatus.ACTIVE,
            'is_core': True,
            'timeout': timeout,
        },
    )
    return engine


def _start_execution(scan: Scan, engine: ScanEngine) -> ScanEngineExecution:
    now = datetime.now(timezone.utc)
    execution, _ = ScanEngineExecution.objects.get_or_create(
        scan=scan,
        engine=engine,
        defaults={'status': ScanEngineExecution.ExecutionStatus.PENDING},
    )
    execution.status = ScanEngineExecution.ExecutionStatus.RUNNING
    execution.progress = 10
    execution.started_at = now
    execution.completed_at = None
    execution.duration = 0
    execution.findings_found = 0
    execution.evidences_collected = 0
    execution.error_message = ''
    execution.logs = ''
    execution.save(update_fields=['status', 'progress', 'started_at', 'completed_at', 'duration', 'findings_found', 'evidences_collected', 'error_message', 'logs', 'updated_at'])
    ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.INFO, message=f'{engine.name} execution started', context={'engine': engine.name})
    return execution


def _first_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return ''


def _severity(value: Any) -> str:
    normalized = _first_string(value).lower()
    return normalized if normalized in set(Vulnerability.Severity.values) else Vulnerability.Severity.INFO


def _risk_score(severity: str) -> float:
    return {
        Vulnerability.Severity.CRITICAL: 95.0,
        Vulnerability.Severity.HIGH: 80.0,
        Vulnerability.Severity.MEDIUM: 60.0,
        Vulnerability.Severity.LOW: 35.0,
        Vulnerability.Severity.INFO: 10.0,
    }[severity]


def _parse_nuclei_findings(raw_output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        info = record.get('info') if isinstance(record.get('info'), dict) else {}
        classification = info.get('classification') if isinstance(info.get('classification'), dict) else {}
        severity = _severity(info.get('severity'))
        title = _first_string(info.get('name')) or _first_string(record.get('template-id')) or 'Nuclei finding'
        description = _first_string(info.get('description')) or 'Finding reported by Nuclei.'
        remediation = _first_string(info.get('remediation'))
        references = info.get('reference') if isinstance(info.get('reference'), list) else []
        cve_ids = classification.get('cve-id') if isinstance(classification.get('cve-id'), list) else []
        cwe_ids = classification.get('cwe-id') if isinstance(classification.get('cwe-id'), list) else []
        matched_at = _first_string(record.get('matched-at')) or _first_string(record.get('host'))
        findings.append({
            'record': record,
            'title': title,
            'description': description,
            'remediation': remediation,
            'severity': severity,
            'references': references,
            'cve_ids': [str(x) for x in cve_ids if str(x).strip()],
            'cwe_id': _first_string(cwe_ids),
            'url': matched_at,
            'method': _first_string(record.get('type')).upper(),
            'template_id': _first_string(record.get('template-id')),
            'matcher_name': _first_string(record.get('matcher-name')),
            'extracted_results': record.get('extracted-results') if isinstance(record.get('extracted-results'), list) else [],
        })
    return findings


def _ingest_nuclei_findings(scan: Scan, evidence: Evidence, raw_output: str) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    for item in _parse_nuclei_findings(raw_output):
        existing = Vulnerability.objects.filter(
            scan=scan,
            asset=scan.asset,
            source_engine='nuclei',
            title=item['title'],
            url=item['url'][:500],
        ).first()
        if existing:
            vulnerability = existing
            vulnerability.last_seen = datetime.now(timezone.utc)
            vulnerability.raw_data = item['record']
            vulnerability.save(update_fields=['last_seen', 'raw_data', 'updated_at'])
        else:
            vulnerability = Vulnerability.objects.create(
                scan=scan,
                project=scan.project,
                asset=scan.asset,
                title=item['title'],
                description=item['description'],
                severity=item['severity'],
                status=Vulnerability.Status.OPEN,
                confidence=Vulnerability.Confidence.HIGH,
                category='web',
                cwe_id=item['cwe_id'],
                cve_ids=item['cve_ids'],
                tags=[x for x in [item['template_id'], item['matcher_name']] if x],
                url=item['url'][:500],
                method=item['method'][:10],
                risk_score=_risk_score(item['severity']),
                evidence_count=0,
                verified_evidence_count=0,
                validation_status='unverified',
                remediation=item['remediation'],
                references=item['references'],
                source_engine='nuclei',
                raw_data=item['record'],
            )
        if not Evidence.objects.filter(pk=evidence.pk, finding=vulnerability).exists():
            evidence.finding = vulnerability
            evidence.save(update_fields=['finding'])
        vulnerability.evidence_count = vulnerability.evidence_records.count()
        vulnerability.save(update_fields=['evidence_count', 'updated_at'])
        findings.append(vulnerability)
    return findings


@shared_task(bind=True, name='fastapi_app.tasks.security_scan.run_nmap_scan', max_retries=1, default_retry_delay=30)
def run_nmap_scan(self, scan_id: str) -> dict:
    scan = Scan.objects.select_related('asset', 'initiated_by', 'project').get(pk=scan_id)
    if not scan.asset:
        raise ValueError('A scan must reference an asset before execution')
    configuration = scan.asset.configuration or {}
    if configuration.get('authorized') is not True:
        scan.status = Scan.Status.FAILED
        scan.error_message = 'Execution blocked: asset is not explicitly marked authorized.'
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        return {'status': 'blocked', 'scan_id': scan_id}
    target = configuration.get('host') or configuration.get('ip') or configuration.get('domain') or configuration.get('url')
    if not target:
        raise ValueError('Authorized asset has no host/ip/domain/url target')
    if not is_target_authorized(target):
        scan.status = Scan.Status.FAILED
        scan.error_message = 'Execution blocked: target is outside the server-side authorized scan scope.'
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        return {'status': 'blocked', 'scan_id': scan_id}
    scan.status = Scan.Status.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.current_phase = 'nmap'
    scan.current_engine = 'nmap'
    scan.progress = 10
    scan.save(update_fields=['status', 'started_at', 'current_phase', 'current_engine', 'progress', 'updated_at'])
    engine = _ensure_engine('nmap', 'Nmap', ScanEngine.EngineCategory.RECON, 300)
    execution = _start_execution(scan, engine)
    try:
        started = scan.started_at
        timeout = 120 if scan.depth == Scan.Depth.QUICK else 300
        result = get_tool('nmap').run(ToolRequest(target=target, authorized=True), timeout=timeout)
        parsed = parse_nmap_xml(result.stdout) if result.stdout.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
        completed_at = datetime.now(timezone.utc)
        duration = max(0, (completed_at - started).total_seconds()) if started else 0
        with transaction.atomic():
            evidence = Evidence.objects.create(scan=scan, asset=scan.asset, source=result.tool, evidence_type='scanner_output', raw_output=result.stdout, metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target, 'parsed': parsed}, collected_by=scan.initiated_by)
            findings = ingest_nmap_findings(scan, evidence, parsed)
            execution.status = ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code == 0 else ScanEngineExecution.ExecutionStatus.FAILED
            execution.progress = 100
            execution.completed_at = completed_at
            execution.duration = duration
            execution.findings_found = len(findings)
            execution.evidences_collected = 1
            execution.result_data = {'tool': result.tool, 'target': result.target, 'exit_code': result.exit_code, 'parsed': parsed, 'evidence_id': str(evidence.id), 'finding_ids': [str(v.id) for v in findings]}
            execution.logs = result.stderr or ''
            execution.save(update_fields=['status', 'progress', 'completed_at', 'duration', 'findings_found', 'evidences_collected', 'result_data', 'logs', 'updated_at'])
            ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.INFO, message='nmap execution completed', context={'target': result.target, 'exit_code': result.exit_code, 'host_count': parsed.get('host_count', 0), 'open_ports': parsed.get('open_ports', 0), 'finding_count': len(findings), 'finding_ids': [str(v.id) for v in findings], 'evidence_id': str(evidence.id)})
            scan.status = Scan.Status.COMPLETED if result.exit_code == 0 else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = completed_at
            scan.findings_count = len(findings)
            scan.engine_results = {**(scan.engine_results or {}), 'nmap': {'exit_code': result.exit_code, 'target': result.target, 'parsed': parsed, 'finding_ids': [str(v.id) for v in findings], 'evidence_id': str(evidence.id)}}
            scan.save(update_fields=['status', 'progress', 'completed_at', 'findings_count', 'engine_results', 'updated_at'])
        return {'status': scan.status, 'scan_id': scan_id, 'tool': 'nmap', 'target': result.target, 'parsed': parsed, 'finding_ids': [str(v.id) for v in findings]}
    except Exception as exc:
        completed_at = datetime.now(timezone.utc)
        execution.status = ScanEngineExecution.ExecutionStatus.FAILED
        execution.progress = 100
        execution.completed_at = completed_at
        execution.error_message = str(exc)
        execution.save(update_fields=['status', 'progress', 'completed_at', 'error_message', 'updated_at'])
        ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.ERROR, message='nmap execution failed', context={'error': str(exc)})
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = completed_at
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        raise


@shared_task(bind=True, name='fastapi_app.tasks.security_scan.run_nuclei_scan', max_retries=1, default_retry_delay=30)
def run_nuclei_scan(self, scan_id: str) -> dict:
    scan = Scan.objects.select_related('asset', 'initiated_by', 'project').get(pk=scan_id)
    if not scan.asset:
        raise ValueError('A scan must reference an asset before execution')
    configuration = scan.asset.configuration or {}
    if configuration.get('authorized') is not True:
        scan.status = Scan.Status.FAILED
        scan.error_message = 'Execution blocked: asset is not explicitly marked authorized.'
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        return {'status': 'blocked', 'scan_id': scan_id}
    target = configuration.get('url')
    if not target:
        raise ValueError('Nuclei requires an authorized http/https URL target')
    if not is_target_authorized(target):
        scan.status = Scan.Status.FAILED
        scan.error_message = 'Execution blocked: target is outside the server-side authorized scan scope.'
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        return {'status': 'blocked', 'scan_id': scan_id}
    scan.status = Scan.Status.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.current_phase = 'nuclei'
    scan.current_engine = 'nuclei'
    scan.progress = 10
    scan.save(update_fields=['status', 'started_at', 'current_phase', 'current_engine', 'progress', 'updated_at'])
    engine = _ensure_engine('nuclei', 'Nuclei', ScanEngine.EngineCategory.ANALYSIS, 600)
    execution = _start_execution(scan, engine)
    try:
        started = scan.started_at
        result = run_nuclei(target, timeout=600)
        completed_at = datetime.now(timezone.utc)
        duration = max(0, (completed_at - started).total_seconds()) if started else 0
        with transaction.atomic():
            evidence = Evidence.objects.create(scan=scan, asset=scan.asset, source=result.tool, evidence_type='scanner_output', raw_output=result.stdout, metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target, 'format': 'jsonl'}, collected_by=scan.initiated_by)
            findings = _ingest_nuclei_findings(scan, evidence, result.stdout)
            execution.status = ScanEngineExecution.ExecutionStatus.COMPLETED if result.exit_code == 0 else ScanEngineExecution.ExecutionStatus.FAILED
            execution.progress = 100
            execution.completed_at = completed_at
            execution.duration = duration
            execution.findings_found = len(findings)
            execution.evidences_collected = 1
            execution.result_data = {'tool': result.tool, 'target': result.target, 'exit_code': result.exit_code, 'result_count': len(findings), 'evidence_id': str(evidence.id), 'finding_ids': [str(v.id) for v in findings]}
            execution.logs = result.stderr or ''
            execution.save(update_fields=['status', 'progress', 'completed_at', 'duration', 'findings_found', 'evidences_collected', 'result_data', 'logs', 'updated_at'])
            ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.INFO, message='nuclei execution completed', context={'target': result.target, 'exit_code': result.exit_code, 'result_count': len(findings), 'evidence_id': str(evidence.id), 'finding_ids': [str(v.id) for v in findings]})
            scan.status = Scan.Status.COMPLETED if result.exit_code == 0 else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = completed_at
            scan.engine_results = {**(scan.engine_results or {}), 'nuclei': {'exit_code': result.exit_code, 'target': result.target, 'result_count': len(findings), 'finding_ids': [str(v.id) for v in findings]}}
            scan.findings_count = Vulnerability.objects.filter(scan=scan).count()
            scan.save(update_fields=['status', 'progress', 'completed_at', 'engine_results', 'findings_count', 'updated_at'])
        return {'status': scan.status, 'scan_id': scan_id, 'tool': 'nuclei', 'target': result.target, 'finding_count': len(findings), 'finding_ids': [str(v.id) for v in findings]}
    except Exception as exc:
        completed_at = datetime.now(timezone.utc)
        execution.status = ScanEngineExecution.ExecutionStatus.FAILED
        execution.progress = 100
        execution.completed_at = completed_at
        execution.error_message = str(exc)
        execution.save(update_fields=['status', 'progress', 'completed_at', 'error_message', 'updated_at'])
        ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.ERROR, message='nuclei execution failed', context={'error': str(exc)})
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = completed_at
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        raise


@shared_task(bind=True, name='fastapi_app.tasks.security_scan.validate_finding_task', max_retries=1, default_retry_delay=30)
def validate_finding_task(self, validation_id: str) -> dict:
    validation = ValidationRun.objects.get(pk=validation_id)
    validation.status = ValidationRun.Status.RUNNING
    validation.progress = 10
    validation.current_phase = 'nmap'
    validation.started_at = datetime.now(timezone.utc)
    validation.save(update_fields=['status', 'progress', 'current_phase', 'started_at'])
    if not validation.authorized:
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = 'Execution blocked: validation is not explicitly authorized.'
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'status': 'blocked', 'validation_id': validation_id}
    if not is_target_authorized(validation.scope or validation.target_value):
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = 'Execution blocked: target is outside the server-side authorized scan scope.'
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'status': 'blocked', 'validation_id': validation_id}
    try:
        result = get_tool('nmap').run(ToolRequest(target=validation.target_value, authorized=True), timeout=300)
        parsed = parse_nmap_xml(result.stdout) if result.stdout.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
        with transaction.atomic():
            Evidence.objects.create(scan=None, asset=None, source=result.tool, evidence_type='validation_output', raw_output=result.stdout, metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target, 'parsed': parsed}, collected_by=validation.user)
            validation.status = ValidationRun.Status.COMPLETED if result.exit_code == 0 else ValidationRun.Status.FAILED
            validation.progress = 100
            validation.current_phase = 'completed' if result.exit_code == 0 else 'failed'
            validation.result = {'tool': result.tool, 'target': result.target, 'exit_code': result.exit_code, 'parsed': parsed}
            validation.completed_at = datetime.now(timezone.utc)
            validation.save(update_fields=['status', 'progress', 'current_phase', 'result', 'completed_at'])
        return {'status': validation.status, 'validation_id': validation_id, 'tool': 'nmap', 'target': result.target, 'parsed': parsed}
    except Exception as exc:
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = str(exc)
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        raise
