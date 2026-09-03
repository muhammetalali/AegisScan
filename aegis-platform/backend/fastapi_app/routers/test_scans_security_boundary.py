from __future__ import annotations

from types import SimpleNamespace

from asgiref.sync import sync_to_async

import pytest
from django.db import connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.routers import scans as scans_router

pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def api_fixture(transactional_db, monkeypatch):
    user = User.objects.create_user(
        email="scan-security-boundary@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Scan",
        last_name="Security",
    )
    project = Project.objects.create(
        name="Scan Security Boundary Regression",
        slug="scan-security-boundary-regression",
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
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot="aegis-scan-target",
        reason="regression fixture",
    )

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        "user_id": str(user.id),
        "is_staff": True,
    }

    def fake_delay(scan_id: str):
        return SimpleNamespace(id=f"test-task-{scan_id}")

    monkeypatch.setattr(scans_router.run_nmap_scan, "delay", fake_delay)

    client = TestClient(app)
    with client:
        try:
            yield client, user, project, asset
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def _body(project_id: str, asset_id: str | None = None) -> dict:
    return {
        "project_id": str(project_id),
        "name": "Security Boundary Scan",
        "scan_type": "network",
        "asset_id": asset_id,
        "engines": ["nmap"],
        "depth": "standard",
        "config": {"target": "aegis-scan-target"},
        "authorized": True,
    }


def test_network_scan_reuses_existing_authorized_asset(api_fixture):
    client, _, project, asset = api_fixture

    response = client.post("/scans/", json=_body(project.id, str(asset.id)))

    assert response.status_code == 201
    scan = Scan.objects.get(id=response.json()["id"])
    assert scan.asset_id == asset.id
    assert Asset.objects.filter(project=project).count() == 1


def test_client_authorized_flag_cannot_create_trusted_asset(api_fixture):
    client, _, project, _ = api_fixture
    body = _body(project.id)
    body["asset_id"] = None
    body["config"]["target"] = "unregistered-target"

    response = client.post("/scans/", json=body)

    assert response.status_code == 400
    assert "existing project asset" in response.json()["detail"]
    assert not Asset.objects.filter(project=project, name="unregistered-target").exists()
    assert not Scan.objects.filter(project=project).exists()


def test_persisted_unauthorized_asset_is_denied(api_fixture):
    client, _, project, asset = api_fixture
    AssetAuthorization.objects.create(
        asset=asset,
        actor=api_fixture[1],
        authorized=False,
        target_snapshot="aegis-scan-target",
        reason="explicit revocation",
    )

    response = client.post("/scans/", json=_body(project.id, str(asset.id)))

    assert response.status_code == 403
    assert "active persisted network authorization" in response.json()["detail"]
    assert not Scan.objects.filter(project=project).exists()


def test_requested_target_must_match_authorization_snapshot(api_fixture):
    client, _, project, asset = api_fixture
    body = _body(project.id, str(asset.id))
    body["config"]["target"] = "different-target"

    response = client.post("/scans/", json=body)

    assert response.status_code == 409
    assert "does not match" in response.json()["detail"]
    assert not Scan.objects.filter(project=project).exists()


def test_legacy_authorization_flag_alone_is_not_a_current_authorization_decision(api_fixture):
    client, _, project, asset = api_fixture
    AssetAuthorization.objects.all().delete()
    asset.configuration = {"host": "aegis-scan-target", "authorized": True}
    asset.save(update_fields=["configuration"])

    response = client.post("/scans/", json=_body(project.id, str(asset.id)))

    assert response.status_code == 403
    assert not Scan.objects.filter(project=project).exists()
