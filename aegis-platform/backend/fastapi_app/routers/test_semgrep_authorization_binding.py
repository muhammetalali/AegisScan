from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from asgiref.sync import async_to_sync
from fastapi import HTTPException

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.routers import scans as scans_router
from fastapi_app.routers.asset_authorization import AuthorizationUpdate, _set_authorization
from fastapi_app.routers.assets import scan_asset
from fastapi_app.routers.scans import ScanCreate, _create_scan, _serialize_scan

pytestmark = pytest.mark.django_db(transaction=True)


def test_semgrep_scan_binds_source_code_authorization_decision():
    user = User.objects.create_user(
        email='semgrep-auth-binding@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Semgrep Authorization Binding',
        slug='semgrep-authorization-binding',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Backend Source',
        slug='backend-source',
        type=Asset.Type.SOURCE_CODE,
        configuration={'path': '/app/e2e'},
    )

    async_to_sync(_set_authorization)(
        str(asset.id),
        str(user.id),
        True,
        AuthorizationUpdate(authorized=True, reason='CI controlled source-code target'),
        uuid4(),
        '127.0.0.1',
        'pytest',
    )

    decision = AssetAuthorization.objects.get(asset=asset)
    assert decision.authorized is True
    assert decision.target_snapshot == '/app/e2e'

    created, engines = async_to_sync(_create_scan)(
        ScanCreate(
            project_id=str(project.id),
            name='Authorized Semgrep Scan',
            scan_type=Scan.Type.CODE,
            asset_id=str(asset.id),
            engines=['semgrep'],
            depth=Scan.Depth.STANDARD,
            config={'path': '/app/e2e'},
        ),
        str(user.id),
    )

    assert engines == ['semgrep']
    assert created.asset_id == asset.id
    assert created.authorization_decision_id == decision.id

    serialized = async_to_sync(_serialize_scan)(created)
    assert serialized.asset_id == str(asset.id)
    assert serialized.authorization_decision_id == str(decision.id)


def test_asset_scan_uses_immutable_ledger_when_mutable_flag_is_stale(monkeypatch):
    user = User.objects.create_user(
        email='asset-scan-ledger-authority@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Asset Scan Ledger Authority',
        slug='asset-scan-ledger-authority',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Ledger-authorized Source',
        slug='ledger-authorized-source',
        type=Asset.Type.SOURCE_CODE,
        configuration={'path': '/app/e2e', 'authorized': False},
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='/app/e2e',
        reason='authoritative ledger grant',
    )

    monkeypatch.setattr(
        scans_router.run_semgrep_scan,
        'delay',
        lambda scan_id: SimpleNamespace(id=f'test-semgrep-{scan_id}'),
    )

    response = async_to_sync(scan_asset)(
        str(asset.id),
        None,
        Scan.Depth.STANDARD,
        {'user_id': str(user.id), 'is_staff': False},
    )

    scan = Scan.objects.get(pk=response['scan_id'])
    asset.refresh_from_db()

    assert asset.configuration['authorized'] is False
    assert scan.authorization_decision_id == decision.id
    assert scan.config.get('authorized') is None
    assert response['asset_id'] == str(asset.id)
    assert response['authorization_decision_id'] == str(decision.id)
    assert response['engine'] == 'semgrep'


def test_asset_scan_rejects_mutable_flag_without_ledger_decision():
    user = User.objects.create_user(
        email='asset-scan-no-ledger@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Asset Scan No Ledger',
        slug='asset-scan-no-ledger',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Mutable-only Source',
        slug='mutable-only-source',
        type=Asset.Type.SOURCE_CODE,
        configuration={'path': '/app/e2e', 'authorized': True},
    )

    with pytest.raises(HTTPException) as exc:
        async_to_sync(scan_asset)(
            str(asset.id),
            None,
            Scan.Depth.STANDARD,
            {'user_id': str(user.id), 'is_staff': False},
        )

    assert exc.value.status_code == 403
    assert 'authoritative authorization decision' in str(exc.value.detail)
    assert Scan.objects.filter(project=project).count() == 0
