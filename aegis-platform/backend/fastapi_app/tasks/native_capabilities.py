from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from fastapi_app.services.authorization_guard import (
    authorization_snapshot,
    require_bound_scan_authorization,
    revalidate_bound_authorization,
)
from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.evidence_identity import evidence_id
from fastapi_app.services.native_output_normalizer import normalize_native_output
from fastapi_app.services.native_tool_runtime import get_native_tool_spec, run_native_tool
from fastapi_app.services.scanner_delivery import terminal_scan_delivery


def _engine(name: str, category: str, timeout: int) -> ScanEngine:
    engine, _ = ScanEngine.objects.get_or_create(
        name=name,
        defaults={
            'display_name': name,
            'description': f'AegisScan native {name} capability engine',
            'category': category,
            'version': 'native-cli',
            'status': ScanEngine.EngineStatus.ACTIVE,
            'is_core': False,
            'timeout': timeout,
        },
    )
    return engine


def _execution(scan: Scan, engine: ScanEngine) -> ScanEngineExecution:
    execution, _ = ScanEngineExecution.objects.get_or_create(
        scan=scan,
        engine=engine,
        defaults={'status': ScanEngineExecution.ExecutionStatus.PENDING},
    )
    execution.status = ScanEngineExecution.ExecutionStatus.RUNNING
    execution.progress = 10
    execution.started_at = datetime.now(timezone.utc)
    execution.completed_at = None
    execution.error_message = ''
    execution.logs = ''
    execution.save(update_fields=['status', 'progress', 'started_at', 'completed_at', 'error_message', 'logs', 'updated_at'])
    return execution


def _fail(scan: Scan, execution: ScanEngineExecution, message: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    execution.status = ScanEngineExecution.ExecutionStatus.FAILED
    execution.progress = 100
    execution.completed_at = now
    execution.error_message = message
    execution.save(update_fields=['status', 'progress', 'completed_at', 'error_message', 'updated_at'])
    ScanLog.objects.create(
        scan=scan,
        engine_execution=execution,
        level=ScanLog.Level.ERROR,
        message='native capability execution failed',
        context={'error': message, **(context or {})},
    )
    scan.status = Scan.Status.FAILED
    scan.error_message = message
    scan.completed_at = now
    scan.progress = 100
    scan.save(update_fields=['status', 'error_message', 'completed_at', 'progress', 'updated_at'])
    return {'status': 'failed', 'scan_id': str(scan.id), 'error': message}


@shared_task(
    bind=True,
    name='fastapi_app.tasks.native_capabilities.run_native_capability_scan',
    max_retries=1,
    default_retry_delay=30,
)
def run_native_capability_scan(self, scan_id: str) -> dict[str, Any]:
    persisted = Scan.objects.select_related('asset', 'project', 'initiated_by').get(pk=scan_id)
    config = persisted.config if isinstance(persisted.config, dict) else {}
    capability_id = str(config.get('capability_id') or '').strip()
    try:
        capability = get_capability(capability_id)
        spec = get_native_tool_spec(capability_id)
    except ValueError as exc:
        engine = _engine('invalid-native-capability', ScanEngine.EngineCategory.ANALYSIS, 60)
        return _fail(persisted, _execution(persisted, engine), str(exc))

    terminal = terminal_scan_delivery(scan_id, capability.tool)
    if terminal:
        return terminal

    scan, target, authorization = require_bound_scan_authorization(scan_id)
    engine_category = (
        ScanEngine.EngineCategory.RECON
        if spec.category in {'network-reconnaissance', 'asset-discovery', 'dns-reconnaissance', 'web-discovery', 'content-discovery', 'web-fingerprinting'}
        else ScanEngine.EngineCategory.ANALYSIS
    )
    engine = _engine(capability.tool, engine_category, spec.timeout)
    if scan is None or authorization is None:
        return _fail(persisted, _execution(persisted, engine), str(target))

    execution = _execution(scan, engine)
    execution.result_data = authorization_snapshot(authorization)
    execution.save(update_fields=['result_data', 'updated_at'])

    options = config.get('capability_options') if isinstance(config.get('capability_options'), dict) else {}
    try:
        result = run_native_tool(capability_id, str(target), options)
        normalized = normalize_native_output(capability_id, result.stdout)
        ok, reason = revalidate_bound_authorization(scan, authorization)
        if not ok:
            return _fail(scan, execution, reason, authorization_snapshot(authorization))

        now = datetime.now(timezone.utc)
        snapshot = authorization_snapshot(authorization)
        with transaction.atomic():
            evidence, _ = Evidence.objects.update_or_create(
                id=evidence_id('scan', scan_id, capability.tool, 'scanner_output'),
                defaults={
                    'scan': scan,
                    'asset': scan.asset,
                    'source': capability.tool,
                    'evidence_type': 'scanner_output',
                    'raw_output': result.stdout,
                    'metadata': {
                        'stderr': result.stderr,
                        'exit_code': result.exit_code,
                        'target': result.target,
                        'capability_id': capability.id,
                        'category': capability.category,
                        'risk': capability.risk,
                        'adapter': capability.adapter,
                        'normalized': normalized,
                        **snapshot,
                    },
                    'collected_by': scan.initiated_by,
                },
            )
            successful = result.exit_code == 0
            execution.status = (
                ScanEngineExecution.ExecutionStatus.COMPLETED
                if successful
                else ScanEngineExecution.ExecutionStatus.FAILED
            )
            execution.progress = 100
            execution.completed_at = now
            execution.evidences_collected = 1
            execution.error_message = '' if successful else result.stderr[:10000]
            execution.result_data = {
                'tool': capability.tool,
                'capability_id': capability.id,
                'target': result.target,
                'exit_code': result.exit_code,
                'scanner_evidence_id': str(evidence.id),
                'observation_count': normalized['count'],
                'finding_ids': [],
                **snapshot,
            }
            execution.save(update_fields=[
                'status', 'progress', 'completed_at', 'evidences_collected',
                'error_message', 'result_data', 'updated_at',
            ])
            scan.status = Scan.Status.COMPLETED if successful else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = now
            scan.engine_results = {**(scan.engine_results or {}), capability.tool: execution.result_data}
            scan.save(update_fields=['status', 'progress', 'completed_at', 'engine_results', 'updated_at'])
        return {
            'status': scan.status,
            'scan_id': scan_id,
            'tool': capability.tool,
            'capability_id': capability.id,
            'target': result.target,
            'evidence_id': str(evidence.id),
            'observation_count': normalized['count'],
            **snapshot,
        }
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        return _fail(scan, execution, str(exc), authorization_snapshot(authorization))
