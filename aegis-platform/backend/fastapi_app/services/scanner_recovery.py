from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.scans.models import Scan, ScanEngineExecution, ScanLog


TERMINAL_EXECUTION_STATUSES = {
    ScanEngineExecution.ExecutionStatus.COMPLETED,
    ScanEngineExecution.ExecutionStatus.FAILED,
    ScanEngineExecution.ExecutionStatus.SKIPPED,
}


def reconcile_stale_scanner_execution(scan_id: str, engine_name: str, *, stale_after_seconds: int = 900) -> dict[str, Any]:
    """Recover a stale RUNNING execution after worker loss without rewinding terminal state."""
    cutoff = timezone.now() - timedelta(seconds=max(1, stale_after_seconds))
    with transaction.atomic():
        scan = Scan.objects.select_for_update().filter(pk=scan_id).first()
        if scan is None:
            return {'status': 'missing', 'scan_id': str(scan_id), 'engine': engine_name}
        execution = (ScanEngineExecution.objects.select_for_update().filter(scan=scan, engine__name=engine_name).select_related('engine').first())
        if execution is None:
            return {'status': 'missing_execution', 'scan_id': str(scan.id), 'engine': engine_name}
        if scan.is_finished or execution.status in TERMINAL_EXECUTION_STATUSES:
            return {'status': 'terminal', 'scan_id': str(scan.id), 'engine': engine_name, 'execution_status': execution.status}
        if execution.status != ScanEngineExecution.ExecutionStatus.RUNNING:
            return {'status': 'active', 'scan_id': str(scan.id), 'engine': engine_name, 'execution_status': execution.status}
        heartbeat = execution.updated_at or execution.started_at
        if heartbeat and heartbeat > cutoff:
            return {'status': 'active', 'scan_id': str(scan.id), 'engine': engine_name, 'execution_status': execution.status}
        execution.status = ScanEngineExecution.ExecutionStatus.PENDING
        execution.progress = 0
        execution.completed_at = None
        execution.error_message = ''
        execution.save(update_fields=['status', 'progress', 'completed_at', 'error_message', 'updated_at'])
        scan.status = Scan.Status.PENDING
        scan.progress = 0
        scan.completed_at = None
        scan.error_message = ''
        scan.save(update_fields=['status', 'progress', 'completed_at', 'error_message', 'updated_at'])
        ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.WARNING, message='stale scanner execution recovered after worker loss', context={'engine': engine_name, 'recovery': 'stale_execution'})
        return {'status': 'recovered', 'scan_id': str(scan.id), 'engine': engine_name, 'execution_status': execution.status}
