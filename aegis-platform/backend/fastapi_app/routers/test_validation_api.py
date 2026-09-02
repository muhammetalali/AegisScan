from __future__ import annotations

from types import SimpleNamespace

import pytest
from asgiref.sync import sync_to_async
from django.db import connections
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
# thread. The handlers access Django ORM through sync_to_async, therefore API
# tests require a transactional DB so fixture-created rows are visible from
# the request thread. The fixture below also requests transactional_db
# explicitly, so this contract cannot be weakened by a future test marker.
pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    """Close the Django ORM connection held by TestClient's thread-sensitive worker."""
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def api_fixture(transactional_db, monkeypatch):
    monkeypatch.setenv("AUTHORIZED_SCAN_TARGETS", "aegis-scan-target")

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

    # Close the HTTP transport and the thread-sensitive Django ORM connection
    # deterministically after each test. Do not start the full application
    # lifespan because these are API contract tests, not service orchestration tests.
    client = TestClient(app)
    try:
        yield client, user, finding
    finally:
        try:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
        finally:
            app.dependency_overrides.clear()
            client.close()


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
        },
    )
    evidence = Evidence.objects.create(
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
    validation.result = {
        **validation.result,
        "evidence_id": str(evidence.id),
    }
    validation.save(update_fields=["result"])
    validation.completed_at = validation.created_at
    validation.save(update_fields=["completed_at"])
    return validation


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


def test_validation_progress_api_returns_not_found_for_unknown_uuid(api_fixture):
    client, _, _ = api_fixture

    response = client.get("/api/v1/validations/00000000-0000-0000-0000-000000000000/progress")

    assert response.status_code == 404
    assert response.json()["detail"] == "Validation not found"


def test_validation_progress_api_rejects_malformed_uuid_without_orm_error(api_fixture):
    client, _, _ = api_fixture

    response = client.get("/api/v1/validations/not-a-uuid/progress")

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "uuid_parsing"


def test_verify_api_returns_409_when_latest_validation_still_detects_finding(api_fixture):
    client, user, finding = api_fixture
    validation = _completed_validation(user, finding, finding_present=True)

    response = client.post(f"/vulnerabilities/{finding.id}/verify")

    assert response.status_code == 409
    assert response.json()["detail"] == "The latest authorized validation still detects the finding; fix cannot be verified."
    finding.refresh_from_db()
    assert finding.validation_status == ""
    assert ValidationRun.objects.filter(id=validation.id).exists()


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