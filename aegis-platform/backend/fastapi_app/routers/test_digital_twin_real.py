import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetRelationship
from django_project.digital_twin.models import DigitalTwin, DigitalTwinNode
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def _context():
    user = User.objects.create_user(email='twin-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Twin E2E', slug='twin-e2e', owner=user)
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    asset_a = Asset.objects.create(project=project, name='web-a', slug='web-a', type=Asset.Type.WEBSITE, configuration={'host': 'example.invalid'}, owner=user)
    asset_b = Asset.objects.create(project=project, name='db-b', slug='db-b', type=Asset.Type.IP_ADDRESS, configuration={'host': '127.0.0.1'}, owner=user)
    AssetRelationship.objects.create(project=project, source=asset_a, target=asset_b, relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO)
    scan = Scan.objects.create(project=project, name='twin scan', scan_type='network', depth='quick', asset=asset_b, engines=['nmap'], config={'target': '127.0.0.1'}, initiated_by=user)
    Vulnerability.objects.create(project=project, asset=asset_b, scan=scan, title='Open port', description='Persisted finding', severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.OPEN, source_engine='nmap', raw_data={'port': 22, 'protocol': 'tcp', 'state': 'open'})
    return user, project, asset_a, asset_b


def teardown_function(_function):
    app.dependency_overrides.clear()


def test_create_build_and_read_real_twin():
    _user, project, asset_a, asset_b = _context()
    client = TestClient(app)
    response = client.post(f'/digital-twin/projects/{project.id}/twins', params={'name': 'production-model'})
    assert response.status_code == 200, response.text
    payload = response.json()
    twin = DigitalTwin.objects.get(pk=payload['id'])
    assert twin.status == DigitalTwin.Status.READY
    assert twin.environment['source'] == 'postgresql'
    assert {node['id'] for node in twin.environment['nodes']} == {str(asset_a.id), str(asset_b.id)}
    assert DigitalTwinNode.objects.filter(twin=twin, asset=asset_a).exists()
    assert len(twin.environment['edges']) == 1
    assert twin.environment['open_finding_count'] == 1
    fetched = client.get(f'/digital-twin/twins/{twin.id}')
    assert fetched.status_code == 200
    assert fetched.json()['status'] == 'ready'


def test_subset_twin_contains_only_selected_assets():
    _user, project, asset_a, asset_b = _context()
    client = TestClient(app)
    twin = client.post(
        f'/digital-twin/projects/{project.id}/twins',
        params=[('name', 'subset-model'), ('assets', str(asset_b.id))],
    )
    assert twin.status_code == 200, twin.text
    payload = twin.json()
    assert [node['id'] for node in payload['environment']['nodes']] == [str(asset_b.id)]
    assert payload['environment']['assets']['total'] == 1
    assert payload['environment']['finding_count'] == 1
    assert payload['environment']['edges'] == []


def test_scenario_is_persisted_and_unknown_node_is_rejected():
    _user, project, _asset_a, asset_b = _context()
    client = TestClient(app)
    twin_id = client.post(f'/digital-twin/projects/{project.id}/twins', params={'name': 'scenario-model'}).json()['id']
    scenario = client.post(f'/digital-twin/twins/{twin_id}/scenarios', json={'name': 'isolate database', 'change_type': 'network_isolation', 'affected_nodes': [str(asset_b.id)], 'parameters': {'reason': 'controlled test'}})
    assert scenario.status_code == 200, scenario.text
    row = scenario.json()
    assert row['status'] == 'pending'
    assert row['affected_nodes'] == [str(asset_b.id)]
    assert row['security_impact'] == 3.0
    bad = client.post(f'/digital-twin/twins/{twin_id}/scenarios', json={'name': 'invalid', 'change_type': 'unknown', 'affected_nodes': ['00000000-0000-0000-0000-000000000000']})
    assert bad.status_code == 422


def test_drift_check_detects_added_project_asset():
    user, project, _asset_a, _asset_b = _context()
    client = TestClient(app)
    twin_id = client.post(f'/digital-twin/projects/{project.id}/twins', params={'name': 'drift-model'}).json()['id']
    extra = Asset.objects.create(project=project, name='new-node', slug='new-node', type=Asset.Type.DOMAIN, configuration={'host': 'new.example.invalid'}, owner=user)
    drift = client.post(f'/digital-twin/twins/{twin_id}/drift-check')
    assert drift.status_code == 200
    payload = drift.json()
    assert payload['drift'] == 1
    assert payload['status'] == 'drifted'
    assert str(extra.id) in payload['extra_in_model']


def test_simulation_fails_closed_without_control_model():
    app.dependency_overrides[get_current_user] = lambda: {'user_id': 'authenticated-test-user'}
    try:
        client = TestClient(app)
        response = client.post('/digital-twin/scenarios/00000000-0000-0000-0000-000000000000/simulate', json={'scenario_id': 'missing'})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 501
