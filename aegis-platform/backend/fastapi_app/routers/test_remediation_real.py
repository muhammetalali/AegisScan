import socket

import pytest
from django.db import close_old_connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from fastapi_app.main import app
from fastapi_app.routers.decision_actions import require_user

pytestmark = pytest.mark.django_db(transaction=True)


def _context():
    user = User.objects.create_user(email='remediation-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Remediation E2E', slug='remediation-e2e', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='remediation-target',
        slug='remediation-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '127.0.0.1', 'authorized': True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='127.0.0.1',
        reason='controlled remediation E2E target',
    )
    scan = Scan.objects.create(
        project=project,
        name='remediation-origin-scan',
        scan_type='network',
        depth='quick',
        asset=asset,
        authorization_decision=authorization,
        engines=['nmap'],
        config={'target': '127.0.0.1'},
        initiated_by=user,
    )
    return user, project, asset, authorization, scan


def test_validated_closure_executes_real_nmap_and_persists_proof():
    user, project, asset, authorization, scan = _context()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title=f'Exposed TCP port {port}',
        description='Controlled remediation E2E finding',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        source_engine='nmap',
        raw_data={'protocol': 'tcp', 'port': port, 'state': 'open'},
        risk_score=9.0,
    )
    app.dependency_overrides[require_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        before = client.get(f'/api/v1/assurance/remediation/findings/{finding.id}')
        assert before.status_code == 200
        response = client.post(
            f'/api/v1/assurance/remediation/findings/{finding.id}/validated-closure',
            json={'reason': 'Close only after real Nmap proves the observed port is absent.'},
        )
    finally:
        listener.close()
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    close_old_connections()
    finding.refresh_from_db()
    validation = ValidationRun.objects.get(pk=payload['validation_id'])
    evidence = Evidence.objects.get(pk=payload['evidence_id'])
    history = VulnerabilityStatusHistory.objects.get(pk=payload['status_history_id'])

    assert payload['state'] == 'verified'
    assert payload['risk_before'] == 9.0
    assert payload['risk_after'] == 0.0
    assert payload['risk_delta'] == -9.0
    assert validation.status == ValidationRun.Status.COMPLETED
    assert finding.status == Vulnerability.Status.FIXED
    assert finding.risk_score == 0.0
    assert evidence.metadata['finding_present'] is False
    assert evidence.finding_id == finding.id
    assert history.vulnerability_id == finding.id
    assert history.new_status == Vulnerability.Status.FIXED
    assert history.changed_by_id == user.id
    assert AuditLog.objects.filter(action=AuditLog.Action.VULN_FIX_VERIFY, resource_id=str(finding.id), result=AuditLog.Result.SUCCESS).exists()


def test_validated_closure_refuses_finding_still_present_without_creating_fix_evidence():
    user, project, asset, authorization, scan = _context()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title=f'Exposed TCP port {port}',
        description='Controlled remediation refusal test',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        source_engine='nmap',
        raw_data={'protocol': 'tcp', 'port': port, 'state': 'open'},
        risk_score=7.0,
    )
    app.dependency_overrides[require_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        response = client.post(
            f'/api/v1/assurance/remediation/findings/{finding.id}/validated-closure',
            json={'reason': 'Should not close while service remains exposed.'},
        )
    finally:
        listener.close()
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    close_old_connections()
    finding.refresh_from_db()
    assert payload['state'] == 'rejected_by_revalidation'
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.risk_score == 7.0
    assert VulnerabilityStatusHistory.objects.filter(vulnerability_id=finding.id, new_status=Vulnerability.Status.FIXED).count() == 0
