import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.posture.models import PostureSnapshot
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.main import app
from fastapi_app.routers.posture import get_posture

pytestmark = pytest.mark.django_db(transaction=True)


def _context():
    user = User.objects.create_user(email='posture-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Posture E2E', slug='posture-e2e', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='posture-target',
        slug='posture-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '127.0.0.1'},
        owner=user,
        is_active=True,
    )
    scan = __import__('django_project.scans.models', fromlist=['Scan']).Scan.objects.create(
        project=project,
        name='posture-scan',
        scan_type='network',
        depth='quick',
        asset=asset,
        engines=['nmap'],
        config={'target': '127.0.0.1'},
        initiated_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='posture finding',
        description='real persisted finding',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        source_engine='nmap',
        raw_data={'port': 22, 'protocol': 'tcp', 'state': 'open'},
    )
    Evidence.objects.create(
        finding=finding,
        asset=asset,
        scan=scan,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<nmaprun><port portid="22"/></nmaprun>',
        metadata={'finding_present': True},
        collected_by=user,
    )
    return user, project


def test_posture_reads_real_database_records():
    user, project = _context()
    app.dependency_overrides[get_posture] = lambda: None
    app.dependency_overrides.clear()

    from fastapi_app.core.dependencies import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        response = client.get(f'/posture/projects/{project.id}/posture')
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload['project_id'] == str(project.id)
    assert payload['overall_score'] != 75.5
    assert payload['metrics'][0]['value'] < 100
    assert payload['metrics'][3]['value'] == 0
    assert payload['recommendations']


def test_posture_evaluation_persists_snapshot_and_history():
    user, project = _context()
    from fastapi_app.core.dependencies import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        evaluate = client.post(f'/posture/projects/{project.id}/evaluate')
        history = client.get(f'/posture/projects/{project.id}/history')
    finally:
        app.dependency_overrides.clear()

    assert evaluate.status_code == 200
    assert history.status_code == 200
    evaluation = evaluate.json()
    assert PostureSnapshot.objects.filter(pk=evaluation['evaluation_id'], project=project).exists()
    rows = history.json()
    assert len(rows) == 1
    assert rows[0]['snapshot_id'] == evaluation['evaluation_id']
