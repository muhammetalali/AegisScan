from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.routers import assets, scans, vulnerabilities


@pytest.mark.django_db
def test_scanner_objects_are_inaccessible_across_tenants():
    owner = User.objects.create_user(email='tenant-owner@example.invalid', password='Strong-Test-Password-123!')
    other = User.objects.create_user(email='tenant-other@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Tenant A', slug='tenant-a', owner=owner)
    foreign_project = Project.objects.create(name='Tenant B', slug='tenant-b', owner=other)

    asset = Asset.objects.create(
        project=project,
        owner=owner,
        name='Tenant A asset',
        slug='tenant-a-asset',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': 'aegis-scan-target', 'authorized': True},
    )
    scan = Scan.objects.create(
        project=project,
        name='Tenant A scan',
        scan_type=Scan.Type.IP,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'host': 'aegis-scan-target'},
        initiated_by=owner,
        status=Scan.Status.COMPLETED,
    )
    vulnerability = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        source_engine='nmap',
        title='Tenant A finding',
        description='Tenant isolation test finding',
        severity=Vulnerability.Severity.MEDIUM,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        remediation='Validate tenant isolation',
        url='http://aegis-scan-target',
    )
    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=vulnerability,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='authorized-e2e-output',
        metadata={'tenant': 'A'},
    )

    assert assets._get_asset_sync(str(asset.id), str(owner.id)) is not None
    assert assets._get_asset_sync(str(asset.id), str(other.id)) is None
    assert scans._get_scan(str(scan.id), str(owner.id)).id == scan.id
    assert scans._get_scan(str(scan.id), str(other.id)) is None
    assert vulnerabilities._get_vulnerability(vulnerability.id, str(owner.id)) is not None
    assert vulnerabilities._get_vulnerability(vulnerability.id, str(other.id)) is None
    foreign_access = vulnerabilities._get_evidences(vulnerability.id, str(other.id))
    assert foreign_access[0] is None
    assert foreign_access[1] == []
    assert evidence.finding_id == vulnerability.id
    assert foreign_project.scans.count() == 0
