from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock

import pytest
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
from django_project.users.models import User
from fastapi_app.services.authorization_guard import require_bound_scan_authorization
from fastapi_app.tasks import advanced_scans, security_scan


@pytest.mark.django_db
def test_mutable_configuration_flag_never_grants_execution(monkeypatch):
    user = User.objects.create_user(email='guard-negative@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Guard Negative', slug='guard-negative', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Target', slug='target', type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target', 'authorized': True})
    scan = Scan.objects.create(project=project, name='Blocked scan', scan_type=Scan.Type.IP, asset=asset, engines=['nmap'], config={'target': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)
    tool = Mock(); monkeypatch.setattr(security_scan, 'get_tool', lambda name: tool)

    result = security_scan.run_nmap_scan.run(str(scan.id))
    scan.refresh_from_db()

    assert result['status'] == 'blocked'
    assert scan.status == Scan.Status.FAILED
    assert tool.run.called is False
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 0
    assert Evidence.objects.filter(scan=scan).count() == 0


@pytest.mark.django_db
def test_expired_authorization_is_blocked(monkeypatch):
    user = User.objects.create_user(email='guard-expired@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Guard Expired', slug='guard-expired', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Target', slug='target', type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target'})
    decision = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='aegis-scan-target', reason='expired test', expires_at=timezone.now() - timedelta(seconds=1))
    scan = Scan.objects.create(project=project, name='Expired scan', scan_type=Scan.Type.IP, asset=asset, authorization_decision=decision, engines=['nmap'], config={'target': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)
    tool = Mock(); monkeypatch.setattr(security_scan, 'get_tool', lambda name: tool)

    result = security_scan.run_nmap_scan.run(str(scan.id))
    scan.refresh_from_db()

    assert result['status'] == 'blocked'
    assert scan.status == Scan.Status.FAILED
    assert tool.run.called is False


@pytest.mark.django_db
def test_superseded_authorization_blocks_queued_scan(monkeypatch):
    user = User.objects.create_user(email='guard-revoked@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Guard Revoked', slug='guard-revoked', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Target', slug='target', type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target', 'authorized': True})
    granted = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='aegis-scan-target', reason='grant')
    scan = Scan.objects.create(project=project, name='Queued scan', scan_type=Scan.Type.IP, asset=asset, authorization_decision=granted, engines=['nmap'], config={'target': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)
    revoked = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=False, target_snapshot='aegis-scan-target', reason='revoked', supersedes=granted)
    asset.configuration = {**asset.configuration, 'authorized': False}; asset.save(update_fields=['configuration', 'updated_at'])
    tool = Mock(); monkeypatch.setattr(security_scan, 'get_tool', lambda name: tool)

    bound_scan, reason, decision = require_bound_scan_authorization(str(scan.id))
    assert bound_scan is None
    assert 'latest asset decision' in reason
    assert decision is None

    result = security_scan.run_nmap_scan.run(str(scan.id)); scan.refresh_from_db()
    assert result['status'] == 'blocked'; assert scan.status == Scan.Status.FAILED; assert tool.run.called is False; assert revoked.id != granted.id


@pytest.mark.django_db
def test_masscan_requires_authoritative_decision(monkeypatch):
    user = User.objects.create_user(email='guard-masscan@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Guard Masscan', slug='guard-masscan', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Network target', slug='network-target', type=Asset.Type.NETWORK_RANGE, configuration={'cidr': 'aegis-scan-target', 'authorized': True})
    scan = Scan.objects.create(project=project, name='Masscan', scan_type=Scan.Type.NETWORK, asset=asset, engines=['masscan'], config={'host': 'aegis-scan-target'}, initiated_by=user, status=Scan.Status.QUEUED)
    tool = Mock(); monkeypatch.setattr(advanced_scans, 'run_masscan', tool)

    result = advanced_scans.run_masscan_scan.run(str(scan.id))
    scan.refresh_from_db()

    assert result['status'] == 'failed'
    assert 'authorization' in result['error'].lower()
    assert tool.called is False
