from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from compliance.models import ComplianceAssessment, ComplianceControl, ComplianceFramework
from evidence.models import ValidationRun
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app
from projects.models import Project
from scans.models import Scan
from assets.models import Asset
from vulnerabilities.models import Vulnerability
from users.models import User

pytestmark = pytest.mark.django_db(transaction=True)


def test_validation_compliance_contract_reads_real_assessments():
    user = User.objects.create_user(email='compliance-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Compliance E2E', slug='compliance-e2e', owner=user)
    asset = Asset.objects.create(project=project, name='Compliance Target', slug='compliance-target', type=Asset.Type.IP_ADDRESS, configuration={'ip': '127.0.0.1'})
    scan = Scan.objects.create(project=project, name='Compliance Scan', scan_type=Scan.Type.IP, asset=asset, initiated_by=user, engines=['nmap'])
    finding = Vulnerability.objects.create(
        project=project, scan=scan, asset=asset, title='Compliance finding', description='Evidence-backed compliance finding',
        severity=Vulnerability.Severity.HIGH, status=Vulnerability.Status.OPEN, risk_score=7.0, source_engine='nmap',
    )
    validation = ValidationRun.objects.create(
        user=user, finding=finding, target_type='ip', target_value='127.0.0.1', scope='127.0.0.1',
        profile='full', engines=['nmap'], authorized=True, status=ValidationRun.Status.COMPLETED, progress=100,
        current_phase='completed', result={'verified': True},
    )
    framework = ComplianceFramework.objects.create(name='Test Framework', framework_type=ComplianceFramework.FrameworkType.CUSTOM, version='1.0')
    control = ComplianceControl.objects.create(framework=framework, control_id='AC-TEST', title='Access control test', description='Controlled compliance contract test')
    assessment = ComplianceAssessment.objects.create(
        project=project, scan=scan, framework=framework, control=control,
        status=ComplianceAssessment.Status.NON_COMPLIANT, evidence='Verified scanner evidence', assessed_by=user,
    )
    assessment.findings.add(finding)

    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        response = TestClient(app).get(f'/api/v1/validations/{validation.id}/compliance')
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload == [{
        'id': str(assessment.id),
        'framework': framework.name,
        'control': control.title,
        'status': 'fail',
        'finding_count': 1,
        'evidence_count': 1,
    }]
