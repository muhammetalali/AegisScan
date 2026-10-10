from __future__ import annotations

import json
from types import SimpleNamespace

from asgiref.sync import sync_to_async

import pytest
from django.db import connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User, UserRole
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.routers import scans as scans_router

pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    """Close the Django ORM connection held by TestClient's thread-sensitive worker."""
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def api_fixture(transactional_db, monkeypatch):
    user = User.objects.create_user(
        email="scan-asset-reuse@example.invalid",
        password="Strong-Test-Password-123!",
        first_name="Scan",
        last_name="Regression",
        role=UserRole.SECURITY_ANALYST,
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
        configuration={"host": "aegis-scan-target"},
        owner=user,
    )
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot="aegis-scan-target",
        reason="scan route contract fixture",
    )

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        "user_id": str(user.id),
        "is_staff": True,
    }

    def fake_delay(scan_id: str):
        return SimpleNamespace(id=f"test-task-{scan_id}")

    monkeypatch.setattr(scans_router.run_nmap_scan, "delay", fake_delay)
    monkeypatch.setattr(scans_router, "require_authorized_target", lambda target, **_kwargs: target)

    client = TestClient(app)
    with client:
        try:
            yield client, user, project, asset
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def _body(project_id: str, asset_id: str) -> dict:
    return {
        "project_id": str(project_id),
        "asset_id": str(asset_id),
        "name": "Repeat Target Scan",
        "scan_type": "network",
        "engines": ["nmap"],
        "depth": "standard",
        "config": {"target": "aegis-scan-target"},
        "authorized": True,
    }


def test_create_scan_reuses_existing_authorized_asset(api_fixture):
    client, _, project, asset = api_fixture

    response = client.post("/scans/", json=_body(project.id, asset.id))

    assert response.status_code == 201
    payload = response.json()
    scan = Scan.objects.get(id=payload["id"])

    assert scan.asset_id == asset.id
    assert Asset.objects.filter(project=project, slug="aegis-scan-target").count() == 1


def test_primary_company_owner_works_across_projects_without_membership(api_fixture, settings):
    from fastapi_app.routers import capabilities as capability_routes

    client, employee, project, asset = api_fixture
    owner = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL,
        password='Owner-Integration-Test-2026!',
    )
    owner.enabled_scan_types = []
    owner.save(update_fields=['enabled_scan_types'])
    assert owner.id != employee.id
    assert not project.members.filter(pk=owner.id).exists()
    assert owner.can_scan_type('network')

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(owner.id), 'is_staff': True,
    }
    assert capability_routes._asset_for_execution.__wrapped__(
        str(asset.id), str(project.id), str(owner.id),
    ) == asset

    response = client.post('/scans/', json=_body(project.id, asset.id))
    assert response.status_code == 201, response.json()
    scan_id = response.json()['id']
    listed = client.get('/scans/')
    assert listed.status_code == 200
    assert scan_id in {row['id'] for row in listed.json()}

    for suffix in ('', '/logs', '/engine-executions'):
        detail = client.get(f'/api/v1/scans/{scan_id}{suffix}')
        assert detail.status_code == 200, detail.text

    asset_detail = client.get(f'/api/v1/assets/{asset.id}')
    assert asset_detail.status_code == 200
    assert asset_detail.json()['id'] == str(asset.id)

    # Bulk creation must honor the same primary-owner grant as other asset routes.
    imported = client.post(
        '/api/v1/assets/bulk-import',
        params={'project_id': str(project.id)},
        files={'file': (
            'company-assets.json',
            json.dumps([{'name': 'owner-cross-project-import', 'type': Asset.Type.IP_ADDRESS}]),
            'application/json',
        )},
    )
    assert imported.status_code == 201, imported.text
    assert len(imported.json()) == 1
    assert Asset.objects.filter(project=project, name='owner-cross-project-import').exists()


def test_create_scan_rejects_authorized_target_drift(api_fixture):
    client, _, project, asset = api_fixture
    asset.configuration = {"host": "different-target"}
    asset.save(update_fields=["configuration"])

    response = client.post("/scans/", json=_body(project.id, asset.id))

    assert response.status_code == 409
    assert "exactly match the authorized asset target" in response.json()["detail"]
    assert Scan.objects.filter(project=project).count() == 0


def test_inactive_asset_legacy_scan_route_rejects_before_dispatch(api_fixture):
    client, _, project, asset = api_fixture
    asset.is_active = False
    asset.save(update_fields=["is_active", "updated_at"])

    response = client.post(f"/api/v1/assets/{asset.id}/scan")

    assert response.status_code == 409
    assert response.json()["detail"] == "Asset is inactive and cannot be scanned"
    assert Scan.objects.filter(project=project).count() == 0


def test_manual_idempotency_key_reuses_existing_scan_without_second_dispatch(api_fixture, monkeypatch):
    client, _, project, asset = api_fixture
    calls = []

    def counted_delay(scan_id):
        calls.append(scan_id)
        return SimpleNamespace(id=f"test-task-{scan_id}")

    monkeypatch.setattr(scans_router.run_nmap_scan, "delay", counted_delay)
    payload = {**_body(project.id, asset.id), "idempotency_key": "repeat.manual.scan-20261008"}

    first = client.post("/scans/", json=payload)
    repeated = client.post("/scans/", json=payload)

    assert first.status_code == 201
    assert repeated.status_code == 201
    assert first.json()["id"] == repeated.json()["id"]
    assert len(calls) == 1
    assert Scan.objects.filter(project=project).count() == 1


def test_manual_idempotency_key_conflict_rejects_changed_options(api_fixture):
    client, _, project, asset = api_fixture
    payload = {**_body(project.id, asset.id), "idempotency_key": "repeat.manual.conflict-20261008"}

    first = client.post("/scans/", json=payload)
    changed = client.post("/scans/", json={**payload, "depth": "deep"})

    assert first.status_code == 201
    assert changed.status_code == 409
    assert "different scan request" in changed.json()["detail"]
    assert Scan.objects.filter(project=project).count() == 1


def test_manual_idempotency_replay_revalidates_authorization(api_fixture):
    client, user, project, asset = api_fixture
    payload = {**_body(project.id, asset.id), "idempotency_key": "repeat.manual.revoked-20261008"}
    assert client.post("/scans/", json=payload).status_code == 201

    AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=False,
        target_snapshot="aegis-scan-target", reason="revoke test scope",
    )
    replay = client.post("/scans/", json=payload)

    assert replay.status_code == 403
    assert Scan.objects.filter(project=project).count() == 1


def test_asset_scan_idempotency_key_reuses_existing_scan(api_fixture, monkeypatch):
    from fastapi_app.routers import assets as assets_router

    client, _, project, asset = api_fixture
    calls = []

    def counted_delay(scan_id):
        calls.append(scan_id)
        return SimpleNamespace(id=f"test-task-{scan_id}")

    monkeypatch.setattr(scans_router.run_nmap_scan, "delay", counted_delay)
    monkeypatch.setattr(assets_router, "require_authorized_target", lambda target: target)
    url = f"/api/v1/assets/{asset.id}/scan?idempotency_key=repeat.asset.scan-20261008"

    first = client.post(url)
    repeated = client.post(url)

    assert first.status_code == 200
    assert repeated.status_code == 200
    assert first.json()["scan_id"] == repeated.json()["scan_id"]
    assert first.json()["idempotency_reused"] is False
    assert repeated.json()["idempotency_reused"] is True
    assert len(calls) == 1
    assert Scan.objects.filter(project=project).count() == 1


def test_rejects_invalid_scan_idempotency_key(api_fixture):
    client, _, project, asset = api_fixture
    payload = {**_body(project.id, asset.id), "idempotency_key": "!bad"}
    response = client.post("/scans/", json=payload)
    assert response.status_code == 400
    assert Scan.objects.filter(project=project).count() == 0


def test_concurrent_same_key_claims_one_scan_atomically(api_fixture):
    """PostgreSQL row locks serialize two real concurrent requests."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from django.db import connections

    _, user, project, asset = api_fixture
    barrier = Barrier(2)
    payload = scans_router.ScanCreate(
        **{
            **_body(project.id, asset.id),
            'idempotency_key': 'concurrent.manual.claim-20261008',
        },
    )

    def submit():
        barrier.wait(timeout=10)
        try:
            # Invoke sync ORM implementation in genuinely independent DB threads.
            return scans_router._create_scan.__wrapped__(payload, str(user.id))
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]

    assert results[0][0].id == results[1][0].id
    assert sorted(r[2] for r in results) == [False, True]
    assert Scan.objects.filter(project=project).count() == 1


def test_intentional_rescans_without_key_remain_distinct(api_fixture):
    client, _, project, asset = api_fixture
    first = client.post('/scans/', json=_body(project.id, asset.id))
    second = client.post('/scans/', json=_body(project.id, asset.id))
    assert first.status_code == second.status_code == 201
    assert first.json()['id'] != second.json()['id']
    assert Scan.objects.filter(project=project).count() == 2
