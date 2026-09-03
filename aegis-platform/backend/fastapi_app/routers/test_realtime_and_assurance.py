from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from django.utils import timezone

from django_project.projects.models import Project
from django_project.assets.models import Asset
from django_project.users.models import User
from enterprise.models import ContinuousAssuranceSchedule, Organization, OrganizationMembership
from enterprise import tasks as enterprise_tasks

from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def test_websocket_rejects_missing_authentication():
    client=TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect('/ws/workflow'):
            pass


def test_continuous_assurance_creates_and_queues_real_scan(monkeypatch):
    user=User.objects.create_user(email='assurance@example.invalid',password='Strong-Test-Password-123!')
    project=Project.objects.create(name='Continuous Assurance',slug='continuous-assurance',owner=user)
    asset=Asset.objects.create(project=project,owner=user,name='Authorized Target',slug='authorized-target',type=Asset.Type.IP_ADDRESS,configuration={'host':'127.0.0.1','authorized':True})
    org=Organization.objects.create(name='Assurance Org',slug='assurance-org',owner=user)
    OrganizationMembership.objects.create(organization=org,user=user,role=OrganizationMembership.Role.OWNER)
    from enterprise.models import TenantProject
    TenantProject.objects.create(organization=org,project=project)
    schedule=ContinuousAssuranceSchedule.objects.create(organization=org,project=project,scan_type='ip',engine='nmap',interval_minutes=60,enabled=True,next_run=timezone.now(),created_by=user)
    calls=[]
    monkeypatch.setattr(enterprise_tasks.run_nmap_scan,'delay',lambda scan_id: calls.append(scan_id) or type('Result',(),{'id':'task-e2e'})())
    result=enterprise_tasks.run_continuous_assurance(schedule.id)
    assert result['status']=='queued'
    assert calls==[result['scan_id']]
    assert project.scans.filter(id=result['scan_id'],engine_results={}).exists() or project.scans.filter(id=result['scan_id']).exists()
    schedule.refresh_from_db()
    assert schedule.last_run is not None
