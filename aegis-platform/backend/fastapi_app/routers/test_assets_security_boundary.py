from __future__ import annotations

import pytest
from asgiref.sync import sync_to_async
from django.db import connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.main import app
from fastapi_app.routers import assets as assets_router

pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def api_fixture(transactional_db):
    owner = User.objects.create_user(
        email="asset-owner-security@example.invalid",
        password="Strong-Test-Password-123!",
    )
    member = User.objects.create_user(
        email="asset-member-security@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Asset Authorization Regression",
        slug="asset-authorization-regression",
        owner=owner,
    )
    project.members.add(member)
    asset = Asset.objects.create(
        project=project,
        name="authorized-target",
        slug="authorized-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "authorized-target"},
        owner=owner,
    )

    def fake_user(user):
        return {"user_id": str(user.id), "is_staff": False}

    app.dependency_overrides[assets_router.get_current_user] = lambda: fake_user(owner)

    client = TestClient(app)
    with client:
        try:
            yield client, owner, member, project, asset, fake_user
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def test_generic_asset_create_cannot_grant_network_authorization(api_fixture):
    client, _, _, project, _, _ = api_fixture
    response = client.post(
        "/assets/",
        json={
            "project_id": str(project.id),
            "name": "new-target",
            "type": "ip_address",
            "configuration": {"host": "new-target", "authorized": True},
        },
    )

    assert response.status_code == 403
    assert "authorization endpoint" in response.json()["detail"]
    assert not Asset.objects.filter(project=project, name="new-target").exists()


def test_generic_asset_update_cannot_grant_network_authorization(api_fixture):
    client, _, _, _, asset, _ = api_fixture
    response = client.patch(
        f"/assets/{asset.id}",
        json={"configuration": {"host": "authorized-target", "authorized": True}},
    )

    assert response.status_code == 403
    asset.refresh_from_db()
    assert (asset.configuration or {}).get("authorized") is not True


def test_only_project_owner_can_authorize_asset(api_fixture):
    client, owner, member, _, asset, fake_user = api_fixture

    app.dependency_overrides[assets_router.get_current_user] = lambda: fake_user(member)
    member_response = client.post(f"/assets/{asset.id}/authorization", json={"authorized": True})
    assert member_response.status_code == 403
    asset.refresh_from_db()
    assert (asset.configuration or {}).get("authorized") is not True

    app.dependency_overrides[assets_router.get_current_user] = lambda: fake_user(owner)
    owner_response = client.post(f"/assets/{asset.id}/authorization", json={"authorized": True})
    assert owner_response.status_code == 200
    asset.refresh_from_db()
    assert (asset.configuration or {}).get("authorized") is True


def test_authorization_endpoint_can_revoke_asset_authorization(api_fixture):
    client, _, _, _, asset, _ = api_fixture
    asset.configuration = {"host": "authorized-target", "authorized": True}
    asset.save(update_fields=["configuration"])

    response = client.post(f"/assets/{asset.id}/authorization", json={"authorized": False})

    assert response.status_code == 200
    asset.refresh_from_db()
    assert (asset.configuration or {}).get("authorized") is False
