"""Regression tests for persisted asset authorization at scan activation."""

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.services import scan_orchestrator as module

pytestmark = pytest.mark.django_db(transaction=True)

@pytest.fixture
def pending_scan():
    user = User.objects.create_user(email='orchestration-check@example.invalid', password='LocalTestPassword123!')
    project = Project.objects.create(name='Permission check', slug='permission-check', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Test host', slug='test-host',
                                 type=Asset.Type.IP_ADDRESS, configuration={'host': 'aegis-scan-target'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True,
                                               target_snapshot='aegis-scan-target', reason='controlled test approval')
    scan = Scan.objects.create(project=project, initiated_by=user, asset=asset,
                               authorization_decision=grant, scan_type=Scan.Type.IP,
                               name='Pending activation', status=Scan.Status.PENDING,
                               engines=['nmap'], config={'target': 'aegis-scan-target'})
    return user, asset, grant, scan


def activate(scan, user):
    orchestrator = module.ScanOrchestrator(websocket_manager=None)
    return orchestrator._queue_scan.__wrapped__(orchestrator, str(scan.pk), str(user.pk))


def assert_not_queued(scan, result):
    assert result['status'] == 'error'
    scan.refresh_from_db()
    assert scan.status == Scan.Status.PENDING
    assert not scan.celery_task_id


def test_missing_bound_decision_blocks_dispatch(pending_scan, monkeypatch):
    user, asset, grant, scan = pending_scan
    scan.authorization_decision = None
    scan.save(update_fields=['authorization_decision'])
    monkeypatch.setattr(module.run_nmap_scan, 'delay', lambda *args: pytest.fail('unexpected dispatch'))
    result = activate(scan, user)
    assert_not_queued(scan, result)
    assert 'bound authorization' in result['message']


def test_newer_revocation_blocks_dispatch(pending_scan, monkeypatch):
    user, asset, grant, scan = pending_scan
    AssetAuthorization.objects.create(asset=asset, actor=user, authorized=False,
                                      target_snapshot='aegis-scan-target', reason='controlled revocation')
    monkeypatch.setattr(module.run_nmap_scan, 'delay', lambda *args: pytest.fail('unexpected dispatch'))
    result = activate(scan, user)
    assert_not_queued(scan, result)
    assert 'no longer the latest' in result['message']


def test_target_drift_blocks_dispatch(pending_scan, monkeypatch):
    user, asset, grant, scan = pending_scan
    asset.configuration = {'host': 'unexpected-drift'}
    asset.save(update_fields=['configuration'])
    monkeypatch.setattr(module.run_nmap_scan, 'delay', lambda *args: pytest.fail('unexpected dispatch'))
    result = activate(scan, user)
    assert_not_queued(scan, result)
    assert 'no longer matches' in result['message']


def test_inactive_asset_blocks_dispatch(pending_scan, monkeypatch):
    user, asset, grant, scan = pending_scan
    asset.is_active = False
    asset.save(update_fields=['is_active'])
    monkeypatch.setattr(module.run_nmap_scan, 'delay', lambda *args: pytest.fail('unexpected dispatch'))
    result = activate(scan, user)
    assert_not_queued(scan, result)
    assert 'inactive' in result['message']


def test_current_authorization_preserves_existing_queue_contract(pending_scan, monkeypatch):
    user, asset, grant, scan = pending_scan
    seen = []
    monkeypatch.setattr(module, 'require_bound_scan_authorization',
                        lambda scan_id: (scan, 'aegis-scan-target', grant))
    monkeypatch.setattr(module, 'checkpoint_scan', lambda *args, **kwargs: None)

    def fake_publish(scan_id):
        seen.append(scan_id)
        return type('Task', (), {'id': 'isolated-test-task-id'})()

    monkeypatch.setattr(module.run_nmap_scan, 'delay', fake_publish)
    result = activate(scan, user)
    assert result['status'] == 'started'
    assert seen == [str(scan.pk)]
    scan.refresh_from_db()
    assert scan.status == Scan.Status.QUEUED
    assert scan.celery_task_id == 'isolated-test-task-id'
