from __future__ import annotations

import pytest
from asgiref.sync import sync_to_async
from django.db import connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.main import app
from fastapi_app.routers import assets as assets_router

pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def source_of_truth_fixture(transactional_db):
    owner = User.objects.create_user(
        email="authorization-ledger-owner@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Authorization Ledger Source Of Truth",
        slug="authorization-ledger-source-of-truth",
        owner=owner,
    )
    asset = Asset.objects.create(
        project=project,
        owner=owner,
        name="ledger-target",
        slug="ledger-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "ledger-target", "authorized": False},
    )

    app.dependency_overrides[assets_router.get_current_user] = lambda: {
        "user_id": str(owner.id),
        "is_staff": False,
    }

    client = TestClient(app)
    with client:
        try:
            yield client, owner, project, asset
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def test_configuration_flag_cannot_preserve_authorization_after_ledger_revocation(source_of_truth_fixture):
    client, owner, _, asset = source_of_truth_fixture
    AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=True,
        target_snapshot="ledger-target",
        reason="temporary assessment authorization",
    )
    AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=False,
        target_snapshot="ledger-target",
        reason="assessment window closed",
    )

    asset.configuration = {"host": "ledger-target", "authorized": True}
    asset.save(update_fields=["configuration"])

    response = client.patch(
        f"/assets/{asset.id}",
        json={"description": "unrelated metadata update"},
    )

    assert response.status_code == 200
    asset.refresh_from_db()
    latest = AssetAuthorization.objects.filter(asset=asset).order_by("-created_at", "-id").first()
    assert latest is not None
    assert latest.authorized is False
    assert (asset.configuration or {}).get("authorized") is True


def test_configuration_change_revokes_from_authorization_ledger_even_if_legacy_flag_is_false(source_of_truth_fixture):
    client, owner, _, asset = source_of_truth_fixture
    AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=True,
        target_snapshot="ledger-target",
        reason="temporary assessment authorization",
    )
    asset.configuration = {"host": "ledger-target", "authorized": False}
    asset.save(update_fields=["configuration"])

    response = client.patch(
        f"/assets/{asset.id}",
        json={"configuration": {"host": "changed-target"}},
    )

    assert response.status_code == 200
    latest = AssetAuthorization.objects.filter(asset=asset).order_by("-created_at", "-id").first()
    assert latest is not None
    assert latest.authorized is False
    assert latest.target_snapshot == "ledger-target"
    assert latest.actor_id == owner.id
