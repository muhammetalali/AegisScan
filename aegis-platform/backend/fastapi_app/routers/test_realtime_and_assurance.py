from __future__ import annotations

import pytest
from asgiref.sync import async_to_sync
from django.db import close_old_connections
from django.utils import timezone
from fastapi.testclient import TestClient

from django_project.projects.models import Project, ProjectMembership
from django_project.assets.models import Asset, AssetAuthorization
from django_project.users.models import User
from enterprise.models import ContinuousAssuranceExecution, ContinuousAssuranceSchedule, Organization, OrganizationMembership, TenantProject
from enterprise import tasks as enterprise_tasks
from fastapi_app.tasks.security_scan import run_nmap_scan
from fastapi_app.routers.enterprise import list_continuous_assurance

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
    execution, created = enterprise_tasks.claim_continuous_assurance_execution(schedule.id, schedule.next_run)
    assert created is True
    result = enterprise_tasks.run_continuous_assurance(execution.id)
    assert result['status'] == 'queued'
    assert calls == [result['scan_id']]
    assert project.scans.filter(id=result['scan_id']).exists()
    scan = project.scans.get(id=result['scan_id'])
    assert scan.asset_id == asset.id
    assert scan.authorization_decision_id == authorization.id
    assert scan.config['assurance_execution_id'] == str(execution.id)
    execution.refresh_from_db()
    assert execution.status == ContinuousAssuranceExecution.Status.QUEUED
    assert execution.scan_id == scan.id
    assert execution.attempts == 1
    schedule.refresh_from_db()
    assert schedule.last_run is not None
    rows = async_to_sync(list_continuous_assurance)(user={'user_id':str(user.id)})
    assert len(rows) == 1
    assert rows[0]['id'] == str(schedule.id)
    assert rows[0]['latest_execution']['scan_id'] == str(scan.id)
    outsider = User.objects.create_user(email='assurance-outsider@example.invalid', password='Strong-Test-Password-123!')
    assert async_to_sync(list_continuous_assurance)(user={'user_id':str(outsider.id)}) == []
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

    execution, _ = enterprise_tasks.claim_continuous_assurance_execution(schedule.id, schedule.next_run)
    result = enterprise_tasks.run_continuous_assurance(execution.id)
    assert result['status'] == 'blocked'
    assert 'not currently valid' in result['reason'] or 'superseded' in result['reason']
    assert project.scans.count() == 0
    schedule.refresh_from_db()
    execution.refresh_from_db()
    assert schedule.enabled is False
    assert schedule.disabled_at is not None
    assert execution.status == ContinuousAssuranceExecution.Status.BLOCKED


def test_continuous_assurance_blocks_after_creator_project_access_is_revoked(monkeypatch):
    owner = User.objects.create_user(email='assurance-owner@example.invalid', password='Strong-Test-Password-123!')
    creator = User.objects.create_user(email='assurance-member@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Membership Bound Assurance', slug='membership-bound-assurance', owner=owner)
    membership = ProjectMembership.objects.create(project=project, user=creator, role=ProjectMembership.Role.ADMIN)
    asset = Asset.objects.create(project=project, owner=creator, name='Member Target', slug='member-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=creator, authorized=True, target_snapshot='127.0.0.1', reason='member grant')
    org = Organization.objects.create(name='Membership Org', slug='membership-org', owner=owner)
    OrganizationMembership.objects.create(organization=org, user=creator, role=OrganizationMembership.Role.ADMIN)
    TenantProject.objects.create(organization=org, project=project)
    schedule = ContinuousAssuranceSchedule.objects.create(organization=org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', next_run=timezone.now(), created_by=creator)
    execution, _ = enterprise_tasks.claim_continuous_assurance_execution(schedule.id, schedule.next_run)
    membership.delete()
    monkeypatch.setattr(run_nmap_scan, 'delay', lambda scan_id: pytest.fail('revoked creator must not enqueue'))

    result = enterprise_tasks.run_continuous_assurance(execution.id)

    assert result['status'] == 'blocked'
    assert result['reason'] == 'Continuous assurance creator no longer has project access.'
    assert project.scans.count() == 0


def test_due_dispatch_claims_one_durable_occurrence_and_advances_before_enqueue(monkeypatch):
    user = User.objects.create_user(email='assurance-dispatch@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Dispatch Assurance', slug='dispatch-assurance', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Dispatch Target', slug='dispatch-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1', reason='dispatch grant')
    org = Organization.objects.create(name='Dispatch Org', slug='dispatch-org', owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role=OrganizationMembership.Role.OWNER)
    TenantProject.objects.create(organization=org, project=project)
    due = timezone.now()
    schedule = ContinuousAssuranceSchedule.objects.create(organization=org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', interval_minutes=60, next_run=due, created_by=user)
    calls = []
    monkeypatch.setattr(enterprise_tasks.run_continuous_assurance, 'delay', lambda execution_id: calls.append(execution_id) or type('Result', (), {'id':'assurance-worker-task'})())

    first = enterprise_tasks.dispatch_due_schedules()
    second = enterprise_tasks.dispatch_due_schedules()

    assert first == {'queued':1,'reports':0,'assurance':1}
    assert second == {'queued':0,'reports':0,'assurance':0}
    assert len(calls) == 1
    execution = ContinuousAssuranceExecution.objects.get(schedule=schedule, scheduled_for=due)
    assert calls == [str(execution.id)]
    assert execution.organization_id == org.id
    assert execution.project_id == project.id
    assert execution.asset_id == asset.id
    assert execution.authorization_decision_id == grant.id
    schedule.refresh_from_db()
    assert schedule.next_run > timezone.now()


def test_continuous_assurance_blocks_cross_tenant_rebinding(monkeypatch):
    user = User.objects.create_user(email='assurance-tenant@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Tenant Bound Assurance', slug='tenant-bound-assurance', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Tenant Target', slug='tenant-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1', reason='tenant grant')
    original_org = Organization.objects.create(name='Original Org', slug='original-assurance-org', owner=user)
    replacement_org = Organization.objects.create(name='Replacement Org', slug='replacement-assurance-org', owner=user)
    OrganizationMembership.objects.create(organization=original_org, user=user, role=OrganizationMembership.Role.OWNER)
    OrganizationMembership.objects.create(organization=replacement_org, user=user, role=OrganizationMembership.Role.OWNER)
    tenant = TenantProject.objects.create(organization=original_org, project=project)
    schedule = ContinuousAssuranceSchedule.objects.create(organization=original_org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', next_run=timezone.now(), created_by=user)
    execution, _ = enterprise_tasks.claim_continuous_assurance_execution(schedule.id, schedule.next_run)
    tenant.organization = replacement_org
    tenant.save(update_fields=['organization'])
    monkeypatch.setattr(run_nmap_scan, 'delay', lambda scan_id: pytest.fail('cross-tenant schedule must not enqueue'))

    result = enterprise_tasks.run_continuous_assurance(execution.id)

    assert result['status'] == 'blocked'
    assert result['reason'] == 'Continuous assurance tenant binding no longer matches the project.'
    assert project.scans.count() == 0


def test_due_dispatch_retries_same_occurrence_after_broker_failure(monkeypatch):
    user = User.objects.create_user(email='assurance-broker@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Broker Recovery Assurance', slug='broker-recovery-assurance', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Broker Target', slug='broker-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1', reason='broker recovery grant')
    org = Organization.objects.create(name='Broker Org', slug='broker-assurance-org', owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role=OrganizationMembership.Role.OWNER)
    TenantProject.objects.create(organization=org, project=project)
    due = timezone.now()
    schedule = ContinuousAssuranceSchedule.objects.create(organization=org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', interval_minutes=60, next_run=due, created_by=user)
    attempts = []
    def enqueue(execution_id):
        attempts.append(execution_id)
        if len(attempts) == 1:
            raise RuntimeError('broker unavailable')
        return type('Result', (), {'id':'recovered-worker-task'})()
    monkeypatch.setattr(enterprise_tasks.run_continuous_assurance, 'delay', enqueue)

    failed = enterprise_tasks.dispatch_due_schedules()
    recovered = enterprise_tasks.dispatch_due_schedules()

    assert failed == {'queued':0,'reports':0,'assurance':1}
    assert recovered == {'queued':1,'reports':0,'assurance':1}
    assert len(set(attempts)) == 1
    assert ContinuousAssuranceExecution.objects.filter(schedule=schedule).count() == 1
    execution = ContinuousAssuranceExecution.objects.get(schedule=schedule)
    assert execution.celery_task_id == 'recovered-worker-task'
    schedule.refresh_from_db()
    assert schedule.next_run > timezone.now()


def test_continuous_assurance_redelivery_replays_one_scan(monkeypatch):
    user = User.objects.create_user(email='assurance-replay@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Replay Assurance', slug='replay-assurance', owner=user)
    asset = Asset.objects.create(project=project, owner=user, name='Replay Target', slug='replay-target', type=Asset.Type.IP_ADDRESS, configuration={'host':'127.0.0.1'})
    grant = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot='127.0.0.1', reason='replay grant')
    org = Organization.objects.create(name='Replay Org', slug='replay-org', owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role=OrganizationMembership.Role.OWNER)
    TenantProject.objects.create(organization=org, project=project)
    schedule = ContinuousAssuranceSchedule.objects.create(organization=org, project=project, asset=asset, authorization_decision=grant, scan_type='ip', engine='nmap', next_run=timezone.now(), created_by=user)
    execution, _ = enterprise_tasks.claim_continuous_assurance_execution(schedule.id, schedule.next_run)
    calls = []
    monkeypatch.setattr(run_nmap_scan, 'delay', lambda scan_id: calls.append(scan_id) or type('Result', (), {'id':'scanner-task'})())

    first = enterprise_tasks.run_continuous_assurance(execution.id)
    second = enterprise_tasks.run_continuous_assurance(execution.id)

    assert first['status'] == second['status'] == 'queued'
    assert first['replayed'] is False
    assert second['replayed'] is True
    assert first['scan_id'] == second['scan_id']
    assert calls == [first['scan_id']]
    assert project.scans.count() == 1
    scan = project.scans.get()
    scan.status = scan.Status.COMPLETED
    scan.completed_at = timezone.now()
    scan.save(update_fields=['status','completed_at','updated_at'])
    execution.refresh_from_db()
    assert execution.status == ContinuousAssuranceExecution.Status.COMPLETED
    assert execution.completed_at == scan.completed_at
    terminal = enterprise_tasks.run_continuous_assurance(execution.id)
    assert terminal['status'] == 'completed'
    assert terminal['replayed'] is True
    assert calls == [first['scan_id']]
