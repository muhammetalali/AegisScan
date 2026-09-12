from __future__ import annotations

import pytest
from asgiref.sync import async_to_sync

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.routers.assets import AssetCreate, _bulk_create_assets


@pytest.mark.django_db(transaction=True)
def test_bulk_import_rolls_back_every_asset_on_persistence_failure(monkeypatch):
    user = User.objects.create_user(
        email='bulk-atomicity@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Bulk atomicity',
        slug='bulk-atomicity',
        owner=user,
    )
    items = [
        AssetCreate(project_id=str(project.id), name='first', type=Asset.Type.IP_ADDRESS),
        AssetCreate(project_id=str(project.id), name='second', type=Asset.Type.DOMAIN),
    ]

    def injected_partial_write_then_failure(objs, *args, **kwargs):
        # Deliberately persist one object before failing. The surrounding
        # transaction.atomic() contract must roll this write back.
        objs[0].save()
        raise RuntimeError('injected bulk persistence failure')

    monkeypatch.setattr(Asset.objects, 'bulk_create', injected_partial_write_then_failure)

    with pytest.raises(RuntimeError, match='injected bulk persistence failure'):
        async_to_sync(_bulk_create_assets)(items, str(user.id))

    assert Asset.objects.filter(project=project).count() == 0


@pytest.mark.django_db
def test_bulk_import_does_not_create_authorization_ledger_decisions():
    user = User.objects.create_user(
        email='bulk-auth@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(name='Bulk auth', slug='bulk-auth', owner=user)
    item = AssetCreate(
        project_id=str(project.id),
        name='imported target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '192.0.2.10', 'authorized': True},
    )

    created = async_to_sync(_bulk_create_assets)([item], str(user.id))

    assert len(created) == 1
    asset = Asset.objects.get(pk=created[0].pk)
    # A legacy configuration flag is never authoritative. Importing an asset
    # must not mint the immutable authorization decision required by scanners.
    assert asset.authorization_records.count() == 0
