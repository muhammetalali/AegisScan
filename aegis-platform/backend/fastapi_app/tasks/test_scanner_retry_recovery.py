from __future__ import annotations

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
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
def test_transient_failure_recovery_preserves_one_durable_operation(monkeypatch):
    user = User.objects.create_user(
        email='retry-recovery@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(name='Retry recovery', slug='retry-recovery', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized target',
        slug='retry-authorized-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': 'aegis-scan-target'},
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='aegis-scan-target',
        reason='retry recovery test authorization',
    )
    scan = Scan.objects.create(
        project=project,
        name='Retry-safe Nmap',
        scan_type=Scan.Type.IP,
        depth=Scan.Depth.QUICK,
        asset=asset,
        authorization_decision=decision,
        engines=['nmap'],
        config={'target': 'aegis-scan-target'},
        initiated_by=user,
        status=Scan.Status.QUEUED,
    )

    class FlakyNmap:
        calls = 0

        def run(self, request, timeout):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError('injected transient scanner failure')
            return ScanResult('nmap', request.target, 0, NMAP_XML, '')

    scanner = FlakyNmap()
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'aegis-scan-target')
    monkeypatch.setattr(security_scan, 'get_tool', lambda name: scanner)

    # Direct task invocation has no broker to schedule the retry, so Celery
    # raises the injected error. The important contract is that the attempt
    # leaves no evidence/finding and does not create a second execution row.
    with pytest.raises(Exception, match='injected transient scanner failure'):
        security_scan.run_nmap_scan.run(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.RUNNING
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 1
    assert Evidence.objects.filter(scan=scan).count() == 0
    assert Vulnerability.objects.filter(scan=scan).count() == 0

    recovered = security_scan.run_nmap_scan.run(str(scan.id))
    duplicate = security_scan.run_nmap_scan.run(str(scan.id))
    scan.refresh_from_db()

    assert recovered['status'] == Scan.Status.COMPLETED
    assert duplicate['status'] == Scan.Status.COMPLETED
    assert duplicate['redelivered'] is True
    assert scan.status == Scan.Status.COMPLETED
    assert scanner.calls == 2
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 1
    assert Evidence.objects.filter(scan=scan, source='nmap', evidence_type='scanner_output').count() == 1
    assert Vulnerability.objects.filter(scan=scan, source_engine='nmap').count() == 1
