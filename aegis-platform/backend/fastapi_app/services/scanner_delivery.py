from __future__ import annotations

from typing import Any

from django_project.scans.models import Scan, ScanEngineExecution


TERMINAL_EXECUTION_STATUSES = {
    ScanEngineExecution.ExecutionStatus.COMPLETED,
    ScanEngineExecution.ExecutionStatus.FAILED,
    ScanEngineExecution.ExecutionStatus.SKIPPED,
}


def terminal_scan_delivery(scan_id: str, engine_name: str) -> dict[str, Any] | None:
    """Return an immutable replay for a scan that is already terminal.

    A redelivered Celery task may replay only a durable engine outcome. The
    worker must never synthesize a terminal result solely from Scan.status.
    """
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None or not scan.is_finished:
        return None

    execution = (
        ScanEngineExecution.objects.filter(scan=scan, engine__name=engine_name)
        .select_related('engine')
        .first()
    )
    if execution is None or execution.status not in TERMINAL_EXECUTION_STATUSES:
        return None

    result = execution.result_data if isinstance(execution.result_data, dict) else {}
    target = result.get('target') or result.get('source')

    return {
        'status': scan.status,
        'scan_id': str(scan.id),
        'tool': engine_name,
        'target': target,
        'finding_ids': result.get('finding_ids', []),
        'error': scan.error_message or None,
        'redelivered': True,
        'terminal': True,
    }
