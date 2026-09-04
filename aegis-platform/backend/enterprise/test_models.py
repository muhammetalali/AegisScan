from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.users.models import User
from .models import OrganizationMembership, TenantProject, DigitalTwin, TwinScenario
from .services import ensure_project_tenant, build_twin, predict_scenario, executive_snapshot


@pytest.mark.django_db
def test_project_tenant_isolated_between_users():
    alice=User.objects.create_user(email='alice@example.invalid',password='Strong-Test-Password-123!',first_name='Alice',last_name='Owner')
    bob=User.objects.create_user(email='bob@example.invalid',password='Strong-Test-Password-123!',first_name='Bob',last_name='Viewer')
    project=Project.objects.create(name='Tenant Project',slug='tenant-project',owner=alice)
    org=ensure_project_tenant(project,str(alice.id))
    assert TenantProject.objects.get(project=project).organization_id == org.id
    assert OrganizationMembership.objects.filter(organization=org,user=alice,is_active=True).exists()
    with pytest.raises(PermissionError):
        ensure_project_tenant(project,str(bob.id))


@pytest.mark.django_db
def test_digital_twin_persists_real_asset_nodes():
    user=User.objects.create_user(email='twin@example.invalid',password='Strong-Test-Password-123!',first_name='Twin',last_name='Owner')
    project=Project.objects.create(name='Twin Project',slug='twin-project',owner=user)
    org=ensure_project_tenant(project,str(user.id))
    asset=Asset.objects.create(project=project,name='Target',slug='target',type=Asset.Type.IP_ADDRESS,configuration={'host':'aegis-scan-target','authorized':True},owner=user)
    twin=DigitalTwin.objects.create(organization=org,project=project,name='Production Twin',source_scan=None)
    built=build_twin(str(twin.id))
    assert built.status == DigitalTwin.Status.READY
    assert built.nodes.filter(kind='asset',external_id=str(asset.id)).exists()


@pytest.mark.django_db
def test_scenario_prediction_is_data_derived_and_persisted():
    user=User.objects.create_user(email='scenario@example.invalid',password='Strong-Test-Password-123!',first_name='Scenario',last_name='Owner')
    project=Project.objects.create(name='Scenario Project',slug='scenario-project',owner=user)
    org=ensure_project_tenant(project,str(user.id))
    twin=DigitalTwin.objects.create(organization=org,project=project,name='Twin')
    scenario=TwinScenario.objects.create(twin=twin,name='Reduce Risk',change_type='remediation',affected_nodes=[],parameters={'risk_reduction':10},created_by=user)
    result=predict_scenario(scenario)
    assert result.status == 'completed'
    assert result.predicted_risk is not None
    assert result.risk_delta <= 0


@pytest.mark.django_db
def test_executive_snapshot_uses_database_state():
    user=User.objects.create_user(email='exec@example.invalid',password='Strong-Test-Password-123!',first_name='Exec',last_name='Owner')
    project=Project.objects.create(name='Executive Project',slug='executive-project',owner=user)
    org=ensure_project_tenant(project,str(user.id))
    snapshot=executive_snapshot(project,org)
    assert snapshot.organization_id == org.id
    assert snapshot.project_id == project.id
