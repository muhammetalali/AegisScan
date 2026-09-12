from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution, ScanLog
from django_project.users.models import User
from fastapi_app.tasks import security_scan


@pytest.mark.django_db
def test_nmap_missing_authoritative_authorization_blocks_before_engine_start(monkeypatch):
    user = User.objects.create_user(email='nmap-invalid@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Nmap invalid target', slug='nmap-invalid-target', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Legacy configured target', slug='legacy-configured-target', type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target', 'authorized': True})
    scan = Scan.objects.create(project=project, name='Nmap blocked', scan_type=Scan.Type.IP, depth=Scan.Depth.QUICK, asset=asset, engines=['nmap'], config={'host': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'aegis-scan-target')
    monkeypatch.setattr(security_scan, 'get_tool', lambda name: pytest.fail('Nmap must not execute without a bound authoritative authorization'))

    result = security_scan.run_nmap_scan.run(str(scan.id))

    scan.refresh_from_db()
    assert result['status'] == 'blocked'
    assert scan.status == Scan.Status.FAILED
    assert scan.completed_at is not None
    assert 'authorization decision' in scan.error_message.lower()
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 0
    assert Evidence.objects.filter(scan=scan).count() == 0
    assert ScanLog.objects.filter(scan=scan, level=ScanLog.Level.WARNING).exists()
