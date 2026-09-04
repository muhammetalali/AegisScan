import pytest
from asgiref.sync import async_to_sync

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from django_project.evidence.models import Evidence, ValidationRun
from fastapi_app.tasks import nmap_finding_validation
from fastapi_app.routers.vulnerabilities import _verify_fix


OPEN_NMAP_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" />
    <address addr="172.18.0.4" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.31.4" />
      </port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1" /></runstats>
</nmaprun>
'''

CLOSED_NMAP_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
  <host>
    <status state="up" />
    <address addr="172.18.0.4" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80">
        <state state="closed" />
        <service name="http" />
      </port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1" /></runstats>
</nmaprun>
'''


@pytest.fixture
def finding_fixture(db):
    user = User.objects.create_user(
        email="validation-regression@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Validation",
        last_name="Regression",
    )
    project = Project.objects.create(
        name="Validation Regression",
        slug="validation-regression",
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name="Authorized Validation Target",
        slug="authorized-validation-target",
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={"host": "aegis-scan-target", "authorized": True},
        owner=user,
    )
    AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=True,
        target_snapshot='aegis-scan-target', reason='Finding validation test grant',
    )
    scan = Scan.objects.create(
        project=project,
        name="Validation Regression Scan",
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
        title="Exposed TCP port 80 (http / nginx)",
        description="Nmap observed an open network service on the authorized asset.",
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
    return user, finding


def _validation(user, finding):
    return ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type="ip",
        target_value="aegis-scan-target",
        scope="aegis-scan-target",
        profile="quick",
        engines=["nmap"],
        authorized=True,
        authorization_decision=finding.asset.authorization_records.first(),
    )


def _stub_nmap(monkeypatch, raw_xml):
    monkeypatch.setattr(
        nmap_finding_validation,
        "_run_nmap_exact",
        lambda target, port, timeout: (0, raw_xml, ""),
    )


@pytest.mark.django_db
def test_nmap_positive_validation_does_not_verify_finding(finding_fixture, monkeypatch):
    user, finding = finding_fixture
    validation = _validation(user, finding)
    _stub_nmap(monkeypatch, OPEN_NMAP_XML)

    result = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))
    finding.refresh_from_db()
    validation.refresh_from_db()

    assert result["finding_present"] is True
    assert validation.status == ValidationRun.Status.COMPLETED
    assert validation.result["finding_present"] is True
    assert finding.validation_status == "unverified"
    evidence = Evidence.objects.get(id=result["evidence_id"])
    assert evidence.finding_id == finding.id
    assert evidence.evidence_type == "validation_output"
    assert evidence.sha256
    assert evidence.metadata["finding_present"] is True

    verified_finding, verification, error = async_to_sync(_verify_fix)(str(finding.id), str(user.id))
    assert verified_finding.id == finding.id
    assert verification.id == validation.id
    assert error == "The latest authorized validation still detects the finding; fix cannot be verified."


@pytest.mark.django_db
def test_nmap_negative_validation_verifies_finding_with_evidence(finding_fixture, monkeypatch):
    user, finding = finding_fixture
    validation = _validation(user, finding)
    _stub_nmap(monkeypatch, CLOSED_NMAP_XML)

    result = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))
    finding.refresh_from_db()
    validation.refresh_from_db()

    assert result["finding_present"] is False
    assert validation.status == ValidationRun.Status.COMPLETED
    assert validation.result["finding_present"] is False
    assert finding.validation_status == "verified"
    assert finding.validated_by_id == user.id
    assert finding.verified_evidence_count == 1
    assert finding.evidence_count == 1

    evidence = Evidence.objects.get(id=result["evidence_id"])
    assert evidence.finding_id == finding.id
    assert evidence.metadata["finding_present"] is False

    verified_finding, verification, error = async_to_sync(_verify_fix)(str(finding.id), str(user.id))
    assert error is None
    assert verification.id == validation.id
    verified_finding.refresh_from_db()
    assert verified_finding.validation_status == "verified"
    assert verified_finding.verified_evidence_count == 1


@pytest.mark.django_db
def test_completed_validation_redelivery_is_idempotent(finding_fixture, monkeypatch):
    user, finding = finding_fixture
    validation = _validation(user, finding)
    calls = 0

    def run_once(target, port, timeout):
        nonlocal calls
        calls += 1
        return 0, CLOSED_NMAP_XML, ''

    monkeypatch.setattr(nmap_finding_validation, '_run_nmap_exact', run_once)

    first = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))
    second = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))

    assert first['status'] == ValidationRun.Status.COMPLETED
    assert second['status'] == ValidationRun.Status.COMPLETED
    assert second['redelivered'] is True
    assert second['evidence_id'] == first['evidence_id']
    assert calls == 1
    assert Evidence.objects.filter(finding=finding, evidence_type='validation_output').count() == 1


@pytest.mark.django_db
def test_nmap_validation_uses_immutable_grant_not_mutable_asset_flag(finding_fixture, monkeypatch):
    user, finding = finding_fixture
    finding.asset.configuration["authorized"] = False
    finding.asset.save(update_fields=["configuration"])
    validation = _validation(user, finding)

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("Nmap execution must not run for an unauthorized asset")

    monkeypatch.setattr(nmap_finding_validation, "_run_nmap_exact", fail_if_called)
    monkeypatch.setattr(nmap_finding_validation, "_run_nmap_exact", lambda *args, **kwargs: (0, CLOSED_NMAP_XML, ''))
    result = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))
    validation.refresh_from_db()

    assert result["status"] == ValidationRun.Status.COMPLETED
    assert validation.status == ValidationRun.Status.COMPLETED
    assert Evidence.objects.filter(finding=finding, evidence_type="validation_output").count() == 1


@pytest.mark.django_db
def test_verify_requires_completed_authorized_finding_validation(finding_fixture):
    user, finding = finding_fixture
    ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type="ip",
        target_value="aegis-scan-target",
        scope="aegis-scan-target",
        profile="quick",
        engines=["nmap"],
        authorized=True,
        status=ValidationRun.Status.RUNNING,
    )

    verified_finding, validation, error = async_to_sync(_verify_fix)(str(finding.id), str(user.id))

    assert verified_finding.id == finding.id
    assert validation is None
    assert error == "Fix verification requires a completed authorized finding-linked validation run."
    finding.refresh_from_db()
    assert finding.validation_status == ""


@pytest.mark.django_db
def test_nmap_validation_requires_exact_target(finding_fixture):
    user, finding = finding_fixture
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type="ip",
        target_value="wrong-target",
        scope="wrong-target",
        profile="quick",
        engines=["nmap"],
        authorized=True,
        authorization_decision=finding.asset.authorization_records.first(),
    )

    result = nmap_finding_validation.validate_nmap_finding_e2e.run(str(validation.id))
    validation.refresh_from_db()
    assert result['status'] == 'blocked'
    assert validation.status == ValidationRun.Status.FAILED
    assert 'requested target does not match' in validation.error_message
