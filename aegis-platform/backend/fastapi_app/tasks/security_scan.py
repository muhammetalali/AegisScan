from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from celery import shared_task
from django.db import transaction

from evidence.models import Evidence
from scans.models import Scan
from ..services.scanner_adapters import run_nmap


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

    scan.status = Scan.Status.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.current_phase = 'nmap'
    scan.current_engine = 'nmap'
    scan.progress = 10
    scan.save(update_fields=['status', 'started_at', 'current_phase', 'current_engine', 'progress', 'updated_at'])

    try:
        timeout = 120 if scan.depth == Scan.Depth.QUICK else 300
        result = run_nmap(target, timeout=timeout)
        with transaction.atomic():
            Evidence.objects.create(
                scan=scan,
                asset=scan.asset,
                source=result.tool,
                evidence_type='scanner_output',
                raw_output=result.stdout,
                metadata={'stderr': result.stderr, 'exit_code': result.exit_code, 'target': result.target},
                collected_by=scan.initiated_by,
            )
            scan.status = Scan.Status.COMPLETED if result.exit_code == 0 else Scan.Status.PARTIAL
            scan.progress = 100
            scan.completed_at = datetime.now(timezone.utc)
            scan.engine_results = {**(scan.engine_results or {}), 'nmap': {'exit_code': result.exit_code, 'target': result.target}}
            scan.save(update_fields=['status', 'progress', 'completed_at', 'engine_results', 'updated_at'])
        return {'status': scan.status, 'scan_id': scan_id, 'tool': 'nmap', 'target': result.target}
    except Exception as exc:
        scan.status = Scan.Status.FAILED
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])
        raise
