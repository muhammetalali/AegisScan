from __future__ import annotations

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution, ScanLog
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.scanner_adapters import ScanResult
from fastapi_app.tasks import security_scan


NMAP_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
  <host>
    <status state="up" />
    <address addr="172.18.0.4" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80"><state state="open" /><service name="http" product="nginx" version="1.27" /></port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1" /></runstats>
</nmaprun>'''


@pytest.mark.django_db
def test_nmap_redelivery_does_not_rerun_or_duplicate_durable_state(monkeypatch):
    user = User.objects.create_user(email='redelivery@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Redelivery', slug='redelivery', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Authorized target', slug='authorized-target', type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target'})
    decision = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='aegis-scan-target', reason='test authorization')
    scan = Scan.objects.create(project=project, name='Idempotent Nmap', scan_type=Scan.Type.IP, depth=Scan.Depth.QUICK, asset=asset, authorization_decision=decision, engines=['nmap'], config={'target': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)

    class StubNmap:
        calls = 0
        def run(self, request, timeout):
            self.calls += 1
            return ScanResult('nmap', request.target, 0, NMAP_XML, '')

    stub = StubNmap(); monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'aegis-scan-target'); monkeypatch.setattr(security_scan, 'get_tool', lambda name: stub)
    first = security_scan.run_nmap_scan.run(str(scan.id)); second = security_scan.run_nmap_scan.run(str(scan.id))
    scan.refresh_from_db()
    assert first['status'] == Scan.Status.COMPLETED; assert second['status'] == Scan.Status.COMPLETED; assert second['redelivered'] is True; assert stub.calls == 1
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 1; assert ScanLog.objects.filter(scan=scan, message='nmap execution started').count() == 1
    assert Vulnerability.objects.filter(scan=scan, source_engine='nmap').count() == 1; assert Evidence.objects.filter(scan=scan, source='nmap', evidence_type='scanner_output').count() == 1
