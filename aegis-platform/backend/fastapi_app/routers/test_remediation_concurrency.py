from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from django_project.evidence.models import ValidationRun
from fastapi_app.routers import remediation as remediation_router


@pytest.mark.django_db(transaction=True)
def test_remediation_create_run_allows_only_one_active_run(monkeypatch):
    user = User.objects.create_user(
        email='remediation-concurrency@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Remediation Concurrency Regression',
        slug='remediation-concurrency-regression',
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
        name='Remediation Concurrency Scan',
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
        description='Authorized regression target',
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
        raw_data={'ip': '172.18.0.4', 'port': 80, 'state': 'open', 'product': 'nginx', 'service': 'http', 'version': '1.31.4', 'protocol': 'tcp'},
    )

    monkeypatch.setattr(
        remediation_router,
        'validate_nmap_finding_e2e',
        SimpleNamespace(delay=lambda validation_id: SimpleNamespace(id=f'task-{validation_id}')),
    )

    create_run = remediation_router._create_run.func
    kwargs = dict(
        finding=finding,
        user_id=str(user.id),
        target_type='ip',
        target_value='aegis-scan-target',
        scope='aegis-scan-target',
        profile='quick',
        engine='nmap',
        reason='concurrency regression',
    )

    def invoke():
        try:
            validation = create_run(**kwargs)
            return ('created', str(validation.id))
        except remediation_router.RemediationValidationConflict as exc:
            return ('conflict', str(exc.validation.id))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: invoke(), range(2)))

    assert sorted(result[0] for result in results) == ['conflict', 'created']
    assert ValidationRun.objects.filter(finding=finding, user=user).filter(
        status__in=[ValidationRun.Status.QUEUED, ValidationRun.Status.RUNNING]
    ).count() == 1
