from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from asgiref.sync import async_to_sync
from django.db import close_old_connections

from django_project.assets.models import Asset, AssetRelationship
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.core.dependencies import get_current_user as core_get_current_user
from fastapi_app.main import app
from fastapi_app.routers.assets import get_current_user as asset_get_current_user
from fastapi.testclient import TestClient

pytestmark = pytest.mark.django_db(transaction=True)


def _auth(user):
    identity = lambda: {'user_id': str(user.id)}
    app.dependency_overrides[core_get_current_user] = identity
    app.dependency_overrides[asset_get_current_user] = identity


def _clear_auth():
    app.dependency_overrides.pop(core_get_current_user, None)
    app.dependency_overrides.pop(asset_get_current_user, None)


def test_negative_scan_scope_is_enforced():
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='negative-scan@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Negative Scan', slug='negative-scan', owner=user)
    with pytest.raises(Exception) as exc:
        async_to_sync(_create_scan)(ScanCreate(project_id=str(project.id), name='blocked', scan_type='network', engines=['nmap'], config={'target': 'not-authorized.invalid'}), str(user.id))
    assert 'authorization' in str(exc.value).lower() or 'authorized' in str(exc.value).lower()


def test_scan_target_is_bound_to_authorized_asset_identity(monkeypatch):
    from fastapi import HTTPException
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='bound-scan@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Bound Scan', slug='bound-scan', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Bound target',
        slug='bound-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '10.30.0.10', 'authorized': True},
    )
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '10.30.0.0/24')

    with pytest.raises(HTTPException) as exc:
        async_to_sync(_create_scan)(
            ScanCreate(
                project_id=str(project.id),
                name='target substitution',
                scan_type='ip',
                asset_id=str(asset.id),
                engines=['nmap'],
                config={'target': '169.254.169.254'},
                authorized=True,
            ),
            str(user.id),
        )

    assert exc.value.status_code == 409
    assert not project.scans.exists()


def test_server_scope_is_required_even_for_authorized_asset(monkeypatch):
    from fastapi import HTTPException
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='server-scope@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Server Scope', slug='server-scope', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Asset authorization alone is insufficient',
        slug='insufficient-authorization',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '10.40.0.10', 'authorized': True},
    )
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '10.50.0.0/24')

    with pytest.raises(HTTPException) as exc:
        async_to_sync(_create_scan)(
            ScanCreate(
                project_id=str(project.id),
                name='outside server scope',
                scan_type='ip',
                asset_id=str(asset.id),
                engines=['nmap'],
            ),
            str(user.id),
        )

    assert exc.value.status_code == 403
    assert not project.scans.exists()


def test_attack_path_persistence_is_idempotent():
    user = User.objects.create_user(email='idempotent@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Idempotency', slug='idempotency', owner=user)
    source = Asset.objects.create(project=project, name='Source', slug='source', type=Asset.Type.WEBSITE, configuration={'internet_exposed': True})
    target = Asset.objects.create(project=project, name='Target', slug='target', type=Asset.Type.CLOUD_RESOURCE, criticality=Asset.Criticality.HIGH)
    AssetRelationship.objects.create(project=project, source=source, target=target, relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO)
    _auth(user)
    try:
        client = TestClient(app)
        body = {'source_asset_id': str(source.id), 'target_asset_id': str(target.id), 'max_hops': 2}
        first = client.post(f'/api/v1/attack-path/projects/{project.id}/analyze', json=body)
        second = client.post(f'/api/v1/attack-path/projects/{project.id}/analyze', json=body)
    finally:
        _clear_auth()
        close_old_connections()
    assert first.status_code == second.status_code == 200
    assert first.json()['persisted_attack_path_ids'] == second.json()['persisted_attack_path_ids']


def test_relationship_creation_is_concurrency_safe():
    user = User.objects.create_user(email='concurrency@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Concurrency', slug='concurrency', owner=user)
    source = Asset.objects.create(project=project, name='Source', slug='source', type=Asset.Type.WEBSITE, configuration={'internet_exposed': True})
    target = Asset.objects.create(project=project, name='Target', slug='target', type=Asset.Type.API_ENDPOINT)
    _auth(user)

    def create_once():
        close_old_connections()
        client = TestClient(app)
        response = client.post(f'/api/v1/assets/{source.id}/relationships', params={'target_id': str(target.id), 'relationship_type': 'connects_to'})
        close_old_connections()
        return response.status_code

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: create_once(), range(2)))
    finally:
        _clear_auth()
        close_old_connections()
    assert all(status in {200, 201} for status in statuses)
    assert AssetRelationship.objects.filter(project=project, source=source, target=target, relationship_type='connects_to').count() == 1
