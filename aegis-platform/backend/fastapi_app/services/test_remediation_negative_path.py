from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state, transition, verify_validation


@pytest.mark.django_db
def test_not_fixed_validation_cannot_be_verified_or_closed():
    user = User.objects.create_user(email='not-fixed@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Negative Remediation', slug='negative-remediation', owner=user)
    asset = Asset.objects.create(project=project, name='Authorized Target', slug='authorized-target', type=Asset.Type.IP_ADDRESS,
                                 environment=Asset.Environment.PRODUCTION, criticality=Asset.Criticality.HIGH,
                                 configuration={'host': 'aegis-scan-target', 'authorized': True}, owner=user)
    scan = Scan.objects.create(project=project, name='Negative Scan', scan_type=Scan.Type.NETWORK, depth=Scan.Depth.QUICK,
                               asset=asset, engines=['nmap'], config={'target': 'aegis-scan-target'}, initiated_by=user)
    finding = Vulnerability.objects.create(scan=scan, project=project, asset=asset, title='Still exposed',
                                            description='Finding remains present', severity=Vulnerability.Severity.INFO,
                                            status=Vulnerability.Status.OPEN, confidence=Vulnerability.Confidence.HIGH,
                                            source_engine='nmap')
    validation = ValidationRun.objects.create(user=user, finding=finding, target_type='ip', target_value='aegis-scan-target',
                                              scope='aegis-scan-target', profile='quick', engines=['nmap'], authorized=True,
                                              status=ValidationRun.Status.COMPLETED,
                                              result={'workflow': 'remediation', 'finding_present': True,
                                                      'remediation_state': RemediationState.NOT_FIXED,
                                                      'remediation_events': []})
    assert get_state(validation) == RemediationState.NOT_FIXED
    with pytest.raises(ValueError, match='still detects the finding'):
        verify_validation(validation.id)
    with pytest.raises(ValueError, match='Invalid remediation transition'):
        transition(validation.id, RemediationState.CLOSED, reason='must not close an unresolved finding')
