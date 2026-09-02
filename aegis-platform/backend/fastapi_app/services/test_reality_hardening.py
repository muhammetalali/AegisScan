from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.routers.posture import _score_for_findings
from fastapi_app.services.nmap_finding_ingestion import ingest_nmap_findings
from fastapi_app.services.scanner_adapters import validate_authorized_target, validate_authorized_web_target, validate_code_target


@pytest.mark.django_db
def test_nmap_ingestion_is_idempotent_for_same_scan_and_raw_evidence():
    user = User.objects.create_user(email='idempotency@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Nmap Idempotency', slug='nmap-idempotency', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='Authorized Target',
        slug='authorized-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={'host': 'aegis-scan-target', 'authorized': True},
        owner=user,
    )
    scan = Scan.objects.create(
        project=project, name='Nmap Idempotency Scan', scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK, asset=asset, engines=['nmap'],
        config={'target': 'aegis-scan-target'}, initiated_by=user,
    )
    parsed = {'hosts': [{'ip': '172.18.0.4', 'ports': [{'port': 80, 'state': 'open', 'product': 'nginx', 'service': 'http', 'version': '1.31.4', 'protocol': 'tcp'}]}]}
    raw = '<nmaprun><port portid="80"><state state="open"/></port></nmaprun>'
    first = Evidence.objects.create(scan=scan, asset=asset, source='nmap', evidence_type='scanner_output', raw_output=raw, collected_by=user)
    findings = ingest_nmap_findings(scan, first, parsed)
    assert len(findings) == 1
    assert Evidence.objects.filter(scan=scan, finding=findings[0], source='nmap', evidence_type='scanner_output').count() == 1

    second = Evidence.objects.create(scan=scan, asset=asset, source='nmap', evidence_type='scanner_output', raw_output=raw, collected_by=user)
    findings_again = ingest_nmap_findings(scan, second, parsed)
    assert findings_again[0].id == findings[0].id
    assert Evidence.objects.filter(scan=scan, finding=findings[0], source='nmap', evidence_type='scanner_output').count() == 1
    assert not Evidence.objects.filter(pk=second.pk).exists()


def test_authorized_target_validation_is_strict():
    assert validate_authorized_target('127.0.0.1') == '127.0.0.1'
    assert validate_authorized_target('example.internal') == 'example.internal'
    with pytest.raises(ValueError):
        validate_authorized_target('http://example.internal')
    with pytest.raises(ValueError):
        validate_authorized_web_target('ftp://example.internal')


def test_code_target_validation_requires_existing_directory(tmp_path: Path):
    assert validate_code_target(str(tmp_path)) == str(tmp_path.resolve())
    with pytest.raises(ValueError):
        validate_code_target(str(tmp_path / 'missing'))


def test_posture_score_uses_finding_state_and_severity():
    findings = [
        SimpleNamespace(severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.OPEN),
        SimpleNamespace(severity=Vulnerability.Severity.INFO, status=Vulnerability.Status.FIXED),
    ]
    assert _score_for_findings(findings) == 80.0
