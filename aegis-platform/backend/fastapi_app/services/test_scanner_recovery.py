from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution
from fastapi_app.services.scanner_recovery import reconcile_stale_scanner_execution


pytestmark = pytest.mark.django_db(transaction=True)


def _execution(scan: Scan, name: str = 'nmap') -> ScanEngineExecution:
    engine, _ = ScanEngine.objects.get_or_create(name=name, defaults={'display_name': name, 'category': ScanEngine.EngineCategory.RECON, 'version': '1', 'status': ScanEngine.EngineStatus.ACTIVE, 'is_core': True, 'timeout': 60})
    return ScanEngineExecution.objects.create(scan=scan, engine=engine, status=ScanEngineExecution.ExecutionStatus.RUNNING, progress=40, started_at=timezone.now() - timedelta(hours=1))


def test_stale_running_execution_is_recovered(scan_factory):
    scan = scan_factory(status=Scan.Status.RUNNING, progress=40)
    execution = _execution(scan)
    ScanEngineExecution.objects.filter(pk=execution.pk).update(updated_at=timezone.now() - timedelta(hours=1))
    result = reconcile_stale_scanner_execution(str(scan.id), 'nmap', stale_after_seconds=60)
    scan.refresh_from_db(); execution.refresh_from_db()
    assert result['status'] == 'recovered'
    assert scan.status == Scan.Status.PENDING
    assert execution.status == ScanEngineExecution.ExecutionStatus.PENDING
    assert ScanEngineExecution.objects.filter(scan=scan, engine=execution.engine).count() == 1


def test_recovery_is_idempotent(scan_factory):
    scan = scan_factory(status=Scan.Status.RUNNING, progress=40)
    execution = _execution(scan)
    ScanEngineExecution.objects.filter(pk=execution.pk).update(updated_at=timezone.now() - timedelta(hours=1))
    first = reconcile_stale_scanner_execution(str(scan.id), 'nmap', stale_after_seconds=60)
    second = reconcile_stale_scanner_execution(str(scan.id), 'nmap', stale_after_seconds=60)
    assert first['status'] == 'recovered'
    assert second['status'] == 'active'
    assert ScanEngineExecution.objects.filter(scan=scan, engine=execution.engine).count() == 1


def test_terminal_execution_is_never_rewound(scan_factory):
    scan = scan_factory(status=Scan.Status.COMPLETED, progress=100)
    execution = _execution(scan)
    execution.status = ScanEngineExecution.ExecutionStatus.COMPLETED
    execution.progress = 100
    execution.completed_at = timezone.now()
    execution.save()
    result = reconcile_stale_scanner_execution(str(scan.id), 'nmap', stale_after_seconds=1)
    scan.refresh_from_db(); execution.refresh_from_db()
    assert result['status'] == 'terminal'
    assert scan.status == Scan.Status.COMPLETED
    assert execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
