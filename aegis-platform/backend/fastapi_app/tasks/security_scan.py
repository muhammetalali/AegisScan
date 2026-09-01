from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence, ValidationRun
from django_project.scans.models import Scan
from ..services.scope_authorization import is_target_authorized
from ..services.nmap_parser import parse_nmap_xml
from ..services.tool_abstraction import ToolRequest, get_tool
from ..services.scanner_adapters import run_nuclei


@shared_task(bind=True, name='fastapi_app.tasks.security_scan.run_nmap_scan', max_retries=1, default_retry_delay=30)
def run_nmap_scan(self, scan_id: str) -> dict:
    scan = Scan.objects.select_related('asset', 'initiated_by').get(pk=scan_id)
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
    try:
        timeout = 120 if scan.depth == Scan.Depth.QUICK else 300
        result = get_tool('nmap').run(ToolRequest(target=target, authorized=True), timeout=timeout)
        parsed = parse_nmap_xml(result.stdout) if result.stdout.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
        with transaction.atomic():
            Evidence.objects.create(scan=scan, asset=scan.asset, source=result.tool, evidence_type='scanner_output', raw_output=result.stdout, metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target, 'parsed': parsed}, collected_by=scan.initiated_by)
            scan.status = Scan.Status.COMPLETED if result.exit_code == 0 else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            scan.findings_count = 0
            scan.engine_results = {**(scan.engine_results or {}), 'nmap': {'exit_code': result.exit_code, 'target': result.target, 'parsed': parsed}}
            scan.save(update_fields=['status', 'progress', 'completed_at', 'findings_count', 'engine_results', 'updated_at'])
        return {'status': scan.status, 'scan_id': scan_id, 'tool': 'nmap', 'target': result.target, 'parsed': parsed}
    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        raise


@shared_task(bind=True, name='fastapi_app.tasks.security_scan.run_nuclei_scan', max_retries=1, default_retry_delay=30)
def run_nuclei_scan(self, scan_id: str) -> dict:
    scan = Scan.objects.select_related('asset', 'initiated_by').get(pk=scan_id)
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
    try:
        result = run_nuclei(target, timeout=600)
        with transaction.atomic():
            Evidence.objects.create(scan=scan, asset=scan.asset, source=result.tool, evidence_type='scanner_output', raw_output=result.stdout, metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target, 'format': 'jsonl'}, collected_by=scan.initiated_by)
            scan.status = Scan.Status.COMPLETED if result.exit_code == 0 else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            scan.engine_results = {**(scan.engine_results or {}), 'nuclei': {'exit_code': result.exit_code, 'target': result.target, 'result_count': len([line for line in result.stdout.splitlines() if line.strip()])}}
            scan.save(update_fields=['status', 'progress', 'completed_at', 'engine_results', 'updated_at'])
        return {'status': scan.status, 'scan_id': scan_id, 'tool': 'nuclei', 'target': result.target}
    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
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
        return {'status': validation.status, 'validation_id': validation_id, 'tool': result.tool, 'target': result.target, 'parsed': parsed}
    except Exception as exc:
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = str(exc)
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        raise
