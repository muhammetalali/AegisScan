from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state, transition


@pytest.mark.django_db
def test_remediation_lifecycle_tracks_verified_and_closed_states():
    user = User.objects.create_user(
        email='remediation-lifecycle@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Remediation Lifecycle Regression',
        slug='remediation-lifecycle-regression',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name='Authorized Target',
        slug='authorized-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={'host': 'aegis-scan-target', 'authorized': True},
        owner=user,
    )
    scan = Scan.objects.create(
        project=project,
        name='Remediation Lifecycle Scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'target': 'aegis-scan-target'},
        initiated_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Exposed TCP port 80',
        description='Authorized lifecycle regression target',
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
        raw_data={'ip': '172.18.0.4', 'port': 80, 'state': 'open', 'product': 'nginx', 'service': 'http', 'version': '1.31.4', 'protocol': 'tcp'},
    )
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type='ip',
        target_value='aegis-scan-target',
        scope='aegis-scan-target',
        profile='quick',
        engines=['nmap'],
        authorized=True,
        result={'workflow': 'remediation'},
    )

    validation = transition(validation.id, RemediationState.REQUESTED, reason='remediation requested')
    assert get_state(validation) == RemediationState.REQUESTED
    assert validation.finding.status == Vulnerability.Status.IN_PROGRESS

    validation = transition(validation.id, RemediationState.VALIDATING, reason='worker started')
    validation = transition(validation.id, RemediationState.VALIDATION_PASSED, reason='finding absent', evidence_id='evidence-1')
    validation = transition(validation.id, RemediationState.VERIFIED, reason='verification accepted', evidence_id='evidence-1')
    assert get_state(validation) == RemediationState.VERIFIED
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding, new_status=Vulnerability.Status.IN_PROGRESS).exists()

    validation = transition(validation.id, RemediationState.CLOSED, reason='verified remediation closed', evidence_id='evidence-1')
    finding.refresh_from_db()
    assert get_state(validation) == RemediationState.CLOSED
    assert finding.status == Vulnerability.Status.FIXED
    assert finding.fixed_at is not None
    assert finding.fixed_by_id == user.id
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding, new_status=Vulnerability.Status.FIXED).exists()

    events = validation.result['remediation_events']
    assert [event['to'] for event in events] == [
        RemediationState.REQUESTED,
        RemediationState.VALIDATING,
        RemediationState.VALIDATION_PASSED,
        RemediationState.VERIFIED,
        RemediationState.CLOSED,
    ]


@pytest.mark.django_db
def test_remediation_lifecycle_rejects_illegal_transition():
    user = User.objects.create_user(
        email='remediation-illegal@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(name='Illegal Transition', slug='illegal-transition', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='Authorized Target',
        slug='authorized-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={'host': 'aegis-scan-target', 'authorized': True},
        owner=user,
    )
    scan = Scan.objects.create(
        project=project,
        name='Illegal Transition Scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'target': 'aegis-scan-target'},
        initiated_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Lifecycle Finding',
        description='Transition guard test',
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
    )
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type='ip',
        target_value='aegis-scan-target',
        scope='aegis-scan-target',
        engines=['nmap'],
        authorized=True,
        result={'workflow': 'remediation', 'remediation_state': RemediationState.REQUESTED, 'remediation_events': []},
    )

    with pytest.raises(ValueError, match='Invalid remediation transition'):
        transition(validation.id, RemediationState.CLOSED, reason='must be rejected')
