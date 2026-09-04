from __future__ import annotations

from typing import Any

from django_project.scans.models import Scan, ScanEngineExecution


def terminal_scan_delivery(scan_id: str, engine_name: str) -> dict[str, Any] | None:
    """Return an immutable replay for a scan that is already terminal.

    This check intentionally runs before authorization revalidation and before
    invoking any scanner binary. A late Celery redelivery must never reopen a
    finished scan, rerun an engine, duplicate evidence, or rewrite historical
    results merely because authorization state changed after completion.
    """
    scan = Scan.objects.filter(pk=scan_id).first()
    if scan is None or not scan.is_finished:
        return None

    execution = (
        ScanEngineExecution.objects.filter(scan=scan, engine__name=engine_name)
        .select_related('engine')
        .first()
    )
    result = execution.result_data if execution and isinstance(execution.result_data, dict) else {}
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
