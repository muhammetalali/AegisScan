import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.reporting.models import Report
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.main import app
from fastapi_app.core.dependencies import get_current_user

pytestmark = pytest.mark.django_db(transaction=True)


def test_reporting_creates_real_persisted_snapshot_and_file():
    user = User.objects.create_user(email='reporting-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Reporting E2E', slug='reporting-e2e', owner=user)
    Asset.objects.create(project=project, name='report-target', slug='report-target', type=Asset.Type.IP_ADDRESS, configuration={'host': '127.0.0.1'}, owner=user)
    Vulnerability.objects.create(project=project, title='E2E finding', description='real persisted finding', severity=Vulnerability.Severity.HIGH,
                                  status=Vulnerability.Status.OPEN, risk_score=8.5)
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        response = client.post('/api/v1/reports/', json={'project_id': str(project.id), 'title': 'E2E Security Report', 'format': 'json', 'report_type': 'security'})
        assert response.status_code == 201, response.text
        payload = response.json()
        detail = client.get(f"/api/v1/reports/{payload['id']}")
        assert detail.status_code == 200, detail.text
        download = client.get(f"/api/v1/reports/{payload['id']}/download")
        assert download.status_code == 200, download.text
    finally:
        app.dependency_overrides.clear()
    report = Report.objects.get(pk=payload['id'])
    assert report.status == Report.Status.COMPLETED
    assert report.snapshot['findings']['high'] == 1
    assert report.snapshot['risk']['aggregate_risk_score'] == 8.5
    assert report.snapshot_sha256
    assert report.file.name.endswith('.json')


def test_reporting_rejects_unsupported_pdf_instead_of_fabricating():
    user = User.objects.create_user(email='reporting-pdf-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Reporting PDF E2E', slug='reporting-pdf-e2e', owner=user)
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        response = TestClient(app).post('/api/v1/reports/', json={'project_id': str(project.id), 'title': 'Unsupported', 'format': 'pdf'})
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 501
