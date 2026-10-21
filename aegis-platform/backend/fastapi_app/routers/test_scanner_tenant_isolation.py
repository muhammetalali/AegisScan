from __future__ import annotations

from asgiref.sync import async_to_sync
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
    assert async_to_sync(scans._get_scan)(str(scan.id), str(owner.id)).id == scan.id
    assert async_to_sync(scans._get_scan)(str(scan.id), str(other.id)) is None
    assert async_to_sync(vulnerabilities._get_vulnerability)(vulnerability.id, str(owner.id)) is not None
    assert async_to_sync(vulnerabilities._get_vulnerability)(vulnerability.id, str(other.id)) is None
    foreign_access = async_to_sync(vulnerabilities._get_evidences)(vulnerability.id, str(other.id))
    assert foreign_access[0] is None
    assert foreign_access[1] == []
    assert evidence.finding_id == vulnerability.id
    assert foreign_project.scans.count() == 0


@pytest.mark.django_db(transaction=True)
def test_limited_security_manager_gets_real_http_404_for_exact_g1_scan_id(settings):
    """Disposable test DB only: verify HTTP hiding, not a production impersonation."""
    from uuid import UUID
    from fastapi.testclient import TestClient
    from django_project.users.models import UserRole
    from fastapi_app.main import app
    from fastapi_app.core.dependencies import get_current_user

    scan_id = UUID('f4fb9b75-c98d-4cf9-b471-0c200c6d5971')
    primary_owner = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL, password='Test-Owner-Only-In-Isolated-DB!'
    )
    limited_manager = User.objects.create_user(
        email='unrelated-manager@example.invalid', password='Test-Manager-Only-In-Isolated-DB!'
    )
    limited_manager.role = UserRole.SECURITY_MANAGER
    limited_manager.save(update_fields=['role'])
    project = Project.objects.create(name='Isolated CIDR project', slug='isolated-g1-cidr', owner=primary_owner)
    asset = Asset.objects.create(
        project=project, owner=primary_owner, name='Approved sample network',
        slug='isolated-g1-asset', type=Asset.Type.NETWORK_RANGE,
        configuration={'cidr': '192.168.49.0/24'},
    )
    Scan.objects.create(
        id=scan_id, project=project, name='Isolated CIDR fixture', asset=asset,
        scan_type=Scan.Type.NETWORK, depth=Scan.Depth.STANDARD,
        engines=['nmap'], config={'cidr': '192.168.49.0/24'},
        initiated_by=primary_owner, status=Scan.Status.COMPLETED,
    )
    target = f'/api/v1/scans/{scan_id}'
    old_overrides = app.dependency_overrides.copy()
    try:
        with TestClient(app) as client:
            app.dependency_overrides[get_current_user] = lambda: {'user_id': str(primary_owner.pk)}
            assert client.get(target).status_code == 200
            app.dependency_overrides[get_current_user] = lambda: {'user_id': str(limited_manager.pk)}
            denied = client.get(target)
            assert denied.status_code == 404, denied.text
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(old_overrides)
