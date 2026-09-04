from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution, ScanLog
from django_project.users.models import User
from fastapi_app.tasks import security_scan


@pytest.mark.django_db
def test_nmap_missing_target_persists_terminal_failure(monkeypatch):
    user = User.objects.create_user(email='nmap-invalid@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Nmap invalid target', slug='nmap-invalid-target', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized but incomplete',
        slug='authorized-but-incomplete',
        type=Asset.Type.IP_ADDRESS,
        configuration={'authorized': True},
    )
    scan = Scan.objects.create(
        project=project,
        name='Nmap missing target',
        scan_type=Scan.Type.IP,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'host': 'missing-from-asset'},
        initiated_by=user,
        status=Scan.Status.QUEUED,
    )
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'aegis-scan-target')
    monkeypatch.setattr(security_scan, 'get_tool', lambda name: pytest.fail('Nmap must not execute when the asset target is missing'))

    result = security_scan.run_nmap_scan.run(str(scan.id))

    scan.refresh_from_db()
    execution = ScanEngineExecution.objects.get(scan=scan)
    assert result['status'] == Scan.Status.FAILED
    assert scan.status == Scan.Status.FAILED
    assert scan.completed_at is not None
    assert 'no host/ip/domain/url target' in scan.error_message.lower()
    assert execution.status == ScanEngineExecution.ExecutionStatus.FAILED
    assert execution.completed_at is not None
    assert execution.progress == 100
    assert execution.error_message == scan.error_message
    assert ScanLog.objects.filter(scan=scan, level=ScanLog.Level.ERROR).exists()
