from __future__ import annotations

import pytest
from django.db import close_old_connections
from django.utils import timezone
from fastapi.testclient import TestClient

from django_project.projects.models import Project
from django_project.assets.models import Asset, AssetAuthorization
from django_project.users.models import User
from enterprise.models import ContinuousAssuranceSchedule, Organization, OrganizationMembership
from enterprise import tasks as enterprise_tasks
from fastapi_app.tasks.security_scan import run_nmap_scan

from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def test_websocket_rejects_missing_authentication():
    try:
        with TestClient(app) as client:
            with pytest.raises(Exception):
                with client.websocket_connect('/ws/workflow'):
                    pass
    finally:
        close_old_connections()


def test_continuous_assurance_creates_and_queues_real_scan(monkeypatch):
    user = User.objects.create_user(email='assurance@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Continuous Assurance', slug='continuous-assurance', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized Target',
        slug='authorized-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '127.0.0.1', 'authorized': True},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1',
        reason='Continuous assurance test grant',
    )
    org = Organization.objects.create(name='Assurance Org', slug='assurance-org', owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role=OrganizationMembership.Role.OWNER)
    from enterprise.models import TenantProject

    TenantProject.objects.create(organization=org, project=project)
    schedule = ContinuousAssuranceSchedule.objects.create(
        organization=org,
        project=project,
        asset=asset,
        authorization_decision=authorization,
        scan_type='ip',
        engine='nmap',
        interval_minutes=60,
        enabled=True,
        next_run=timezone.now(),
        created_by=user,
    )
    calls = []
    monkeypatch.setattr(run_nmap_scan, 'delay', lambda scan_id: calls.append(scan_id) or type('Result', (), {'id': 'task-e2e'})())
    result = enterprise_tasks.run_continuous_assurance(schedule.id)
    assert result['status'] == 'queued'
    assert calls == [result['scan_id']]
    assert project.scans.filter(id=result['scan_id']).exists()
    scan = project.scans.get(id=result['scan_id'])
    assert scan.asset_id == asset.id
    assert scan.authorization_decision_id == authorization.id
    schedule.refresh_from_db()
    assert schedule.last_run is not None
    close_old_connections()


def test_continuous_assurance_rejects_superseded_authorization(monkeypatch):
    user = User.objects.create_user(email='assurance-revoked@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Revoked Assurance', slug='revoked-assurance', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Target', slug='revoked-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1', reason='initial grant')
    AssetAuthorization.objects.create(asset=asset, actor=user, authorized=False, target_snapshot='127.0.0.1', reason='revoked', supersedes=grant)
    org = Organization.objects.create(name='Revoked Org', slug='revoked-org', owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role=OrganizationMembership.Role.OWNER)
    schedule = ContinuousAssuranceSchedule.objects.create(organization=org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', next_run=timezone.now(), created_by=user)
    monkeypatch.setattr(run_nmap_scan, 'delay', lambda scan_id: pytest.fail('revoked schedule must not enqueue'))

    with pytest.raises(ValueError, match='not currently valid|superseded'):
        enterprise_tasks.run_continuous_assurance(schedule.id)
    assert project.scans.count() == 0
