from __future__ import annotations

import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.remediation_lifecycle import (
    RemediationState,
    get_state,
    verify_validation,
)


def _build_validation_fixture():
    user = User.objects.create_user(
        email="remediation-verification@example.invalid",
        password="Strong-Test-Password-123!",
    )

    project = Project.objects.create(
        name="Remediation Verification Regression",
        slug="remediation-verification-regression",
        owner=user,
    )

    asset = Asset.objects.create(
        project=project,
        name="Authorized Target",
        slug="authorized-target",
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={
            "host": "aegis-scan-target",
            "authorized": True,
        },
        owner=user,
    )

    scan = Scan.objects.create(
        project=project,
        name="Remediation Verification Scan",
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=["nmap"],
        config={"target": "aegis-scan-target"},
        initiated_by=user,
    )

    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title="Exposed TCP port 80",
        description="Verification regression finding",
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine="nmap",
        raw_data={
            "ip": "172.18.0.4",
            "port": 80,
            "state": "open",
            "product": "nginx",
            "service": "http",
            "version": "1.31.4",
            "protocol": "tcp",
        },
    )

    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type="ip",
        target_value="aegis-scan-target",
        scope="aegis-scan-target",
        profile="quick",
        engines=["nmap"],
        authorized=True,
        status=ValidationRun.Status.COMPLETED,
        progress=100,
        current_phase="completed",
        result={
            "workflow": "remediation",
            "finding_present": False,
        },
    )

    return user, project, asset, scan, finding, validation


@pytest.mark.django_db
def test_remediation_verification_requires_real_linked_evidence():
    user, project, asset, scan, finding, validation = _build_validation_fixture()

    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=finding,
        source="nmap",
        evidence_type="validation_output",
        raw_output=(
            "<nmaprun>"
            '<host>'
            '<address addr="172.18.0.4" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="closed"/>'
            "</port></ports>"
            "</host>"
            "</nmaprun>"
        ),
        metadata={
            "validation_id": str(validation.id),
            "target": "aegis-scan-target",
            "finding_present": False,
            "exit_code": 0,
        },
        collected_by=user,
    )

    validation.result["evidence_id"] = str(evidence.id)
    validation.save(update_fields=["result"])

    verified = verify_validation(validation.id)

    assert get_state(verified) == RemediationState.VERIFIED

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.IN_PROGRESS

    verified_evidence = Evidence.objects.get(pk=evidence.id)
    assert verified_evidence.finding_id == finding.id
    assert len(verified_evidence.sha256) == 64
    assert verified_evidence.metadata["validation_id"] == str(validation.id)

    events = verified.result["remediation_events"]

    assert [event["to"] for event in events] == [
        RemediationState.VERIFIED,
    ]

    assert all(
        event["evidence_id"] == str(evidence.id)
        for event in events
    )


@pytest.mark.django_db
def test_remediation_verification_rejects_evidence_from_another_finding():
    user, project, asset, scan, finding, validation = _build_validation_fixture()

    other_finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title="Different finding",
        description="Evidence ownership regression target",
        severity=Vulnerability.Severity.INFO,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine="nmap",
    )

    wrong_evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=other_finding,
        source="nmap",
        evidence_type="validation_output",
        raw_output="<nmaprun><host><ports/></host></nmaprun>",
        metadata={
            "validation_id": str(validation.id),
            "finding_present": False,
        },
        collected_by=user,
    )

    validation.result["evidence_id"] = str(wrong_evidence.id)
    validation.save(update_fields=["result"])

    with pytest.raises(
        ValueError,
        match="linked validation evidence does not belong to this finding",
    ):
        verify_validation(validation.id)
