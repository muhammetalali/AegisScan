from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from django_project.evidence.models import Evidence, ValidationRun
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.routers import validations as validations_router


# FastAPI TestClient executes async endpoints outside pytest-django's main test
# thread. The API handlers intentionally access Django ORM through
# sync_to_async, so these regression tests must use a transactional database
# fixture to make the fixture-created rows visible to the ORM connection used
# by the request thread.
pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def api_fixture(db):
    user = User.objects.create_user(
        email="validation-api-regression@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Validation",
        last_name="API",
    )
    project = Project.objects.create(
        name="Validation API Regression",
        slug="validation-api-regression",
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name="Authorized API Target",
        slug="authorized-api-target",
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={"host": "aegis-scan-target", "authorized": True},
        owner=user,
    )
    scan = Scan.objects.create(
        project=project,
        name="Validation API Regression Scan",
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

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        "user_id": str(user.id),
        "is_staff": True,
    }
    client = TestClient(app)

    yield client, user, finding

    app.dependency_overrides.clear()


def _create_body(finding_id: str) -> dict:
    return {
        "finding_id": finding_id,
        "target_type": "ip",
        "target_value": "aegis-scan-target",
        "profile": "quick",
        "engines": ["nmap"],
        "scope": "aegis-scan-target",
        "authorized": True,
        "include_subdomains": False,
        "duration_minutes": 5,
        "rate_limit": 5,
        "extra": {},
    }


def _completed_validation(user, finding, *, finding_present: bool) -> ValidationRun:
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
            "tool": "nmap",
            "target": "aegis-scan-target",
            "exit_code": 0,
            "finding_present": finding_present,
            "evidence_id": "00000000-0000-0000-0000-000000000001",
        },
    )
    validation.completed_at = validation.created_at
    validation.save(update_fields=["completed_at"])
    Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source="nmap",
        evidence_type="validation_output",
        raw_output="<nmaprun />" if finding_present else "<nmaprun><closed /></nmaprun>",
        metadata={
            "format": "xml",
            "target": "aegis-scan-target",
            "validation_id": str(validation.id),
            "finding_present": finding_present,
        },
        collected_by=user,
    )
    return validation


@pytest.mark.django_db
def test_validation_create_api_persists_finding_link_and_queues_task(api_fixture, monkeypatch):
    client, user, finding = api_fixture
    called = {}

    def fake_delay(validation_id: str):
        called["validation_id"] = validation_id
        return SimpleNamespace(id="api-regression-task-id")

    monkeypatch.setattr(validations_router, "validate_nmap_finding_e2e", SimpleNamespace(delay=fake_delay))

    response = client.post("/api/v1/validations", json=_create_body(str(finding.id)))

    assert response.status_code == 201
    payload = response.json()
    assert payload["finding_id"] == str(finding.id)
    assert payload["status"] == "queued"
    assert payload["engines"] == ["nmap"]
    assert called["validation_id"] == payload["id"]

    validation = ValidationRun.objects.get(id=payload["id"])
    assert validation.user_id == user.id
    assert validation.finding_id == finding.id
    assert validation.authorized is True
    assert validation.celery_task_id == "api-regression-task-id"


@pytest.mark.django_db
def test_validation_create_api_rejects_wrong_target_before_queue(api_fixture, monkeypatch):
    client, _, finding = api_fixture
    called = False

    def fail_delay(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("queue must not be reached when target does not match finding asset")

    monkeypatch.setattr(validations_router, "validate_nmap_finding_e2e", SimpleNamespace(delay=fail_delay))
    body = _create_body(str(finding.id))
    body["target_value"] = "wrong-target"

    response = client.post("/api/v1/validations", json=body)

    assert response.status_code == 400
    assert "exactly match" in response.json()["detail"]
    assert called is False


@pytest.mark.django_db
def test_validation_progress_api_returns_not_found_for_unknown_uuid(api_fixture):
    client, _, _ = api_fixture

    response = client.get("/api/v1/validations/00000000-0000-0000-0000-000000000000/progress")

    assert response.status_code == 404
    assert response.json()["detail"] == "Validation not found"


@pytest.mark.django_db
def test_validation_progress_api_rejects_malformed_uuid_without_orm_error(api_fixture):
    client, _, _ = api_fixture

    response = client.get("/api/v1/validations/not-a-uuid/progress")

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "uuid_parsing"


@pytest.mark.django_db
def test_verify_api_returns_409_when_latest_validation_still_detects_finding(api_fixture):
    client, user, finding = api_fixture
    validation = _completed_validation(user, finding, finding_present=True)

    response = client.post(f"/vulnerabilities/{finding.id}/verify")

    assert response.status_code == 409
    assert response.json()["detail"] == "The latest authorized validation still detects the finding; fix cannot be verified."
    finding.refresh_from_db()
    assert finding.validation_status == ""
    assert ValidationRun.objects.filter(id=validation.id).exists()


@pytest.mark.django_db
def test_verify_api_returns_verified_for_completed_negative_validation(api_fixture):
    client, user, finding = api_fixture
    validation = _completed_validation(user, finding, finding_present=False)

    response = client.post(f"/vulnerabilities/{finding.id}/verify")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "verified"
    assert payload["vulnerability_id"] == str(finding.id)
    assert payload["validation_id"] == str(validation.id)
    assert payload["verified_evidence_count"] == 1
    assert payload["validated_at"]

    finding.refresh_from_db()
    assert finding.validation_status == "verified"
    assert finding.validated_by_id == user.id
    assert finding.verified_evidence_count == 1


@pytest.mark.django_db
def test_verify_api_requires_finding_linked_completed_authorized_validation(api_fixture):
    client, user, finding = api_fixture
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

    response = client.post(f"/vulnerabilities/{finding.id}/verify")

    assert response.status_code == 409
    assert response.json()["detail"] == "Fix verification requires a completed authorized finding-linked validation run."
