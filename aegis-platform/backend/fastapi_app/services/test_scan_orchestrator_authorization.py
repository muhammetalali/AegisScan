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


def test_primary_owner_can_control_company_scan_without_membership(pending_scan, settings, monkeypatch):
    from django_project.projects.models import ProjectMembership
    from types import SimpleNamespace

    employee, asset, grant, scan = pending_scan
    owner = User.objects.create_superuser(
        email='primary-orchestrator@example.invalid', password='Owner-Test-Password123!',
    )
    settings.AEGIS_PRIMARY_OWNER_EMAIL = owner.email
    assert not ProjectMembership.objects.filter(project=scan.project, user=owner).exists()

    orchestrator = module.ScanOrchestrator(websocket_manager=None)
    assert orchestrator._has_scan_access.__wrapped__(orchestrator, str(scan.pk), str(owner.pk))
    progress = orchestrator._get_progress.__wrapped__(orchestrator, str(scan.pk), str(owner.pk))
    assert progress['status'] == Scan.Status.PENDING

    monkeypatch.setattr(module, 'require_bound_scan_authorization',
                        lambda scan_id: (scan, 'aegis-scan-target', grant))
    monkeypatch.setattr(module, 'checkpoint_scan', lambda *args, **kwargs: None)
    monkeypatch.setattr(module.run_nmap_scan, 'delay',
                        lambda scan_id: SimpleNamespace(id='owner-test-task'))
    result = activate(scan, owner)
    assert result['status'] == 'started'


def test_nonmember_employee_cannot_read_or_start_company_scan(pending_scan, settings, monkeypatch):
    employee, asset, grant, scan = pending_scan
    settings.AEGIS_PRIMARY_OWNER_EMAIL = 'different-owner@example.invalid'
    outsider = User.objects.create_user(
        email='outsider-orchestrator@example.invalid', password='Test-Password123!',
    )
    orchestrator = module.ScanOrchestrator(websocket_manager=None)
    assert not orchestrator._has_scan_access.__wrapped__(orchestrator, str(scan.pk), str(outsider.pk))
    assert orchestrator._get_progress.__wrapped__(orchestrator, str(scan.pk), str(outsider.pk))['status'] == 'error'
    monkeypatch.setattr(module.run_nmap_scan, 'delay', lambda *_: pytest.fail('unexpected dispatch'))
    assert_not_queued(scan, activate(scan, outsider))


def test_primary_owner_can_transition_and_prepare_restart_without_project_membership(
        pending_scan, settings, monkeypatch):
    from django_project.projects.models import ProjectMembership
    from fastapi_app.services import scan_state_machine as state_machine
    from types import SimpleNamespace

    employee, asset, grant, scan = pending_scan
    owner = User.objects.create_superuser(
        email='owner-state-machine@example.invalid', password='Owner-Test-Password123!',
    )
    settings.AEGIS_PRIMARY_OWNER_EMAIL = owner.email
    assert not ProjectMembership.objects.filter(project=scan.project, user=owner).exists()
    monkeypatch.setattr(
        state_machine, 'checkpoint_scan',
        lambda *args, **kwargs: SimpleNamespace(id='test-checkpoint', resume_token='test-resume'),
    )
    cancelled = state_machine.transition_scan(
        scan_id=str(scan.pk), user_id=str(owner.pk), target_status=Scan.Status.CANCELLED,
    )
    assert cancelled['status'] == Scan.Status.CANCELLED
    restarted = state_machine.prepare_restart(scan_id=str(scan.pk), user_id=str(owner.pk))
    assert restarted['status'] == 'restart_ready'


@pytest.mark.asyncio
async def test_primary_engine_list_equals_supported_registered_tasks():
    from fastapi_app.routers.scans import SUPPORTED_ENGINES, _PRIMARY_SCAN_TASKS
    from fastapi_app.services.capability_registry import CAPABILITIES

    registry_tools = {
        capability.tool for capability in CAPABILITIES.values()
        if capability.adapter == 'specialized'
    }
    entries = await module.ScanOrchestrator(websocket_manager=None).list_engines()
    listed = {entry['name'] for entry in entries}
    assert len(entries) == len(listed), 'duplicate primary engine listings'
    assert listed == registry_tools == SUPPORTED_ENGINES == set(_PRIMARY_SCAN_TASKS)
    assert listed == set(module.ENGINE_TASKS)
    assert all(entry['execution'] == 'real' for entry in entries)
    assert all(entry['status'] == 'active' for entry in entries)
    assert all(entry['name'] in _PRIMARY_SCAN_TASKS for entry in entries)



def test_manual_and_orchestrated_primary_dispatch_share_existing_real_tasks():
    from fastapi_app.routers import scans

    assert scans._PRIMARY_SCAN_TASKS is module.ENGINE_TASKS
    assert set(module.ENGINE_TASKS) == {'nmap', 'nuclei', 'masscan', 'semgrep'}
    assert module.ENGINE_TASKS['masscan'] is scans._PRIMARY_SCAN_TASKS['masscan']
    assert module.ENGINE_TASKS['semgrep'] is scans._PRIMARY_SCAN_TASKS['semgrep']
