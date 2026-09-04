from __future__ import annotations

from uuid import uuid4

import pytest
from asgiref.sync import async_to_sync

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.routers.asset_authorization import AuthorizationUpdate, _set_authorization
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
