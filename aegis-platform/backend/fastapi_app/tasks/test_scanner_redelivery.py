from __future__ import annotations

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.scanner_adapters import ScanResult
from fastapi_app.tasks import advanced_scans, security_scan


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


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('engine_name', 'scan_type', 'asset_type', 'configuration', 'terminal_status', 'execution_status'),
    [
        ('nmap', Scan.Type.IP, Asset.Type.IP_ADDRESS, {'host': 'terminal-nmap'}, Scan.Status.COMPLETED, ScanEngineExecution.ExecutionStatus.COMPLETED),
        ('nuclei', Scan.Type.URL, Asset.Type.WEBSITE, {'url': 'http://terminal-nuclei.invalid'}, Scan.Status.FAILED, ScanEngineExecution.ExecutionStatus.FAILED),
        ('masscan', Scan.Type.NETWORK, Asset.Type.NETWORK_RANGE, {'cidr': '10.77.0.0/24'}, Scan.Status.PARTIAL, ScanEngineExecution.ExecutionStatus.FAILED),
        ('semgrep', Scan.Type.CODE, Asset.Type.SOURCE_CODE, {'path': '/tmp/terminal-semgrep'}, Scan.Status.CANCELLED, ScanEngineExecution.ExecutionStatus.SKIPPED),
    ],
)
def test_terminal_redelivery_is_read_only_before_authorization_or_engine_execution(
    monkeypatch,
    engine_name,
    scan_type,
    asset_type,
    configuration,
    terminal_status,
    execution_status,
):
    user = User.objects.create_user(email=f'terminal-{engine_name}@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name=f'Terminal {engine_name}', slug=f'terminal-{engine_name}', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name=f'{engine_name} target', slug=f'{engine_name}-target', type=asset_type, configuration=configuration)
    scan = Scan.objects.create(
        project=project,
        name=f'Terminal {engine_name}',
        scan_type=scan_type,
        depth=Scan.Depth.QUICK,
        asset=asset,
        authorization_decision=None,
        engines=[engine_name],
        config={},
        initiated_by=user,
        status=terminal_status,
        progress=100,
        error_message='durable terminal outcome' if terminal_status != Scan.Status.COMPLETED else '',
    )
    engine = ScanEngine.objects.create(
        name=engine_name,
        display_name=engine_name.title(),
        category=ScanEngine.EngineCategory.RECON if engine_name in {'nmap', 'masscan'} else ScanEngine.EngineCategory.ANALYSIS,
        status=ScanEngine.EngineStatus.ACTIVE,
    )
    execution = ScanEngineExecution.objects.create(
        scan=scan,
        engine=engine,
        status=execution_status,
        progress=100,
        result_data={'target': configuration.get('host') or configuration.get('url') or configuration.get('cidr'), 'source': configuration.get('path'), 'finding_ids': ['durable-finding']},
    )

    def must_not_run(*_args, **_kwargs):
        raise AssertionError('terminal redelivery invoked a scanner binary')

    if engine_name == 'nmap':
        monkeypatch.setattr(security_scan, 'get_tool', must_not_run)
        task = security_scan.run_nmap_scan
    elif engine_name == 'nuclei':
        monkeypatch.setattr(security_scan, 'run_nuclei', must_not_run)
        task = security_scan.run_nuclei_scan
    elif engine_name == 'masscan':
        monkeypatch.setattr(advanced_scans, 'run_masscan', must_not_run)
        task = advanced_scans.run_masscan_scan
    else:
        monkeypatch.setattr(advanced_scans, 'run_semgrep', must_not_run)
        task = advanced_scans.run_semgrep_scan

    before = {
        'executions': ScanEngineExecution.objects.filter(scan=scan).count(),
        'logs': ScanLog.objects.filter(scan=scan).count(),
        'evidence': Evidence.objects.filter(scan=scan).count(),
        'findings': Vulnerability.objects.filter(scan=scan).count(),
    }
    result = task.run(str(scan.id))
    scan.refresh_from_db(); execution.refresh_from_db()

    assert result['status'] == terminal_status
    assert result['redelivered'] is True
    assert result['terminal'] is True
    assert scan.status == terminal_status
    assert scan.progress == 100
    assert execution.status == execution_status
    assert ScanEngineExecution.objects.filter(scan=scan).count() == before['executions']
    assert ScanLog.objects.filter(scan=scan).count() == before['logs']
    assert Evidence.objects.filter(scan=scan).count() == before['evidence']
    assert Vulnerability.objects.filter(scan=scan).count() == before['findings']
