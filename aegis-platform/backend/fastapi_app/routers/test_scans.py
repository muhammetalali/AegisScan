from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.routers import scans as scans_router

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def api_fixture(transactional_db, monkeypatch):
    user = User.objects.create_user(
        email="scan-asset-reuse@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Scan",
        last_name="Regression",
    )
    project = Project.objects.create(
        name="Scan Asset Reuse Regression",
        slug="scan-asset-reuse-regression",
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name="aegis-scan-target",
        slug="aegis-scan-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "aegis-scan-target", "authorized": True},
        owner=user,
    )

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        "user_id": str(user.id),
        "is_staff": True,
    }

    def fake_delay(scan_id: str):
        return SimpleNamespace(id=f"test-task-{scan_id}")

    monkeypatch.setattr(scans_router.run_nmap_scan, "delay", fake_delay)

    client = TestClient(app)
    try:
        yield client, user, project, asset
    finally:
        app.dependency_overrides.clear()
        client.close()


def _body(project_id: str) -> dict:
    return {
        "project_id": str(project_id),
        "name": "Repeat Target Scan",
        "scan_type": "network",
        "engines": ["nmap"],
        "depth": "standard",
        "config": {"target": "aegis-scan-target"},
        "authorized": True,
    }


def test_create_scan_reuses_existing_authorized_asset(api_fixture):
    client, _, project, asset = api_fixture

    response = client.post("/scans/", json=_body(project.id))

    assert response.status_code == 201
    payload = response.json()
    scan = Scan.objects.get(id=payload["id"])

    assert scan.asset_id == asset.id
    assert Asset.objects.filter(project=project, slug="aegis-scan-target").count() == 1


def test_create_scan_rejects_slug_collision_with_different_identity(api_fixture):
    client, _, project, _ = api_fixture
    conflicting = Asset.objects.get(project=project, slug="aegis-scan-target")
    conflicting.configuration = {"host": "different-target", "authorized": True}
    conflicting.save(update_fields=["configuration"])

    response = client.post("/scans/", json=_body(project.id))

    assert response.status_code == 409
    assert "different identity" in response.json()["detail"]
    assert Scan.objects.filter(project=project).count() == 0
