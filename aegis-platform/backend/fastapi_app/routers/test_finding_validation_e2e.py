from __future__ import annotations

import hashlib
import socket

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.tasks.nmap_finding_validation import validate_nmap_finding_e2e

pytestmark = pytest.mark.django_db(transaction=True)


def _context(user, target='127.0.0.1'):
    project = Project.objects.create(name='Validation E2E', slug='validation-e2e', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='loopback-validation-target',
        slug='loopback-validation-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': target, 'authorized': True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='controlled validation E2E target',
    )
    scan = Scan.objects.create(
        project=project,
        name='Origin Nmap scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        authorization_decision=authorization,
        engines=['nmap'],
        config={'target': target},
        initiated_by=user,
    )
    return project, asset, authorization, scan


def _validation(user, finding, authorization, target='127.0.0.1'):
    return ValidationRun.objects.create(
        user=user,
        finding=finding,
        finding_identity_snapshot=finding.id,
        authorization_decision=authorization,
        target_type='ip',
        target_value=target,
        scope=target,
        profile='quick',
        engines=['nmap'],
        authorized=True,
    )


def _finding(scan, project, asset, port):
    return Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title=f'Exposed TCP port {port}',
        description='Nmap observed an open TCP service during the originating scan.',
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
        raw_data={'protocol': 'tcp', 'port': port, 'state': 'open'},
    )


def test_real_nmap_finding_validation_persists_positive_evidence(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1')
    user = User.objects.create_user(email='validation-e2e@example.invalid', password='Strong-Test-Password-123!')
    project, asset, authorization, scan = _context(user)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        finding = _finding(scan, project, asset, port)
        validation = _validation(user, finding, authorization)
        result = validate_nmap_finding_e2e.run(str(validation.id))
    finally:
        listener.close()

    validation.refresh_from_db()
    finding.refresh_from_db()
    evidence = Evidence.objects.get(pk=result['evidence_id'])

    assert result['target'] == '127.0.0.1'
    assert result['finding_present'] is True
    assert validation.status == ValidationRun.Status.COMPLETED
    assert validation.authorization_decision_id == authorization.id
    assert finding.validation_status == 'unverified'
    assert evidence.finding_id == finding.id
    assert evidence.metadata['authorization_decision_id'] == str(authorization.id)
    assert evidence.metadata['finding_present'] is True
    assert evidence.raw_output.strip()
    assert evidence.sha256 == hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest()


def test_real_nmap_finding_validation_proves_absence_after_listener_closes(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1')
    user = User.objects.create_user(email='validation-negative-e2e@example.invalid', password='Strong-Test-Password-123!')
    project, asset, authorization, scan = _context(user)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    listener.close()

    finding = _finding(scan, project, asset, port)
    validation = _validation(user, finding, authorization)
    result = validate_nmap_finding_e2e.run(str(validation.id))

    finding.refresh_from_db()
    validation.refresh_from_db()
    evidence = Evidence.objects.get(pk=result['evidence_id'])

    assert result['finding_present'] is False
    assert validation.status == ValidationRun.Status.COMPLETED
    assert finding.validation_status == 'verified'
    assert finding.verified_evidence_count == 1
    assert evidence.metadata['finding_present'] is False


def test_queued_validation_is_rejected_after_authorization_revocation(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1')
    user = User.objects.create_user(email='validation-revocation-e2e@example.invalid', password='Strong-Test-Password-123!')
    project, asset, authorization, scan = _context(user)
    finding = _finding(scan, project, asset, 1)
    validation = _validation(user, finding, authorization)
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot='127.0.0.1',
        reason='revoked before worker execution',
        supersedes=authorization,
    )

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError('Nmap must not execute after authorization revocation')

    monkeypatch.setattr('fastapi_app.tasks.nmap_finding_validation._run_nmap_exact', fail_if_called)
    result = validate_nmap_finding_e2e.run(str(validation.id))
    validation.refresh_from_db()

    assert called is False
    assert result['status'] == 'blocked' or validation.status == ValidationRun.Status.FAILED
    assert 'no longer the latest' in validation.error_message or 'currently valid' in validation.error_message
    assert not Evidence.objects.filter(finding=finding, evidence_type='validation_output').exists()
