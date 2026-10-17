"""Regression proof that asset listing is scoped and paginated in the database."""

from __future__ import annotations

from asgiref.sync import async_to_sync
from django.db import connection
from django.test.utils import CaptureQueriesContext
import pytest

from django_project.assets.models import Asset
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.routers.assets import _accessible_assets


@pytest.mark.django_db(transaction=True)
def test_unsearched_assets_are_filtered_and_paginated_in_sql():
    user = User.objects.create_user(
        email="asset-page-owner@example.invalid", password="Strong-Test-Password-123!"
    )
    other = User.objects.create_user(
        email="asset-page-other@example.invalid", password="Strong-Test-Password-123!"
    )
    project = Project.objects.create(name="Owned asset page", slug="owned-asset-page", owner=user)
    outsider = Project.objects.create(name="Other asset page", slug="other-asset-page", owner=other)
    for i in range(6):
        Asset.objects.create(
            project=project, owner=user, name=f"target-{i}",
            slug=f"target-{i}", type=Asset.Type.IP_ADDRESS,
            environment=Asset.Environment.PRODUCTION if i != 0 else Asset.Environment.STAGING,
            is_active=i != 5,
        )
    Asset.objects.create(
        project=outsider, owner=other, name="hidden", slug="hidden",
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
    )

    with CaptureQueriesContext(connection) as queries:
        page = async_to_sync(_accessible_assets)(
            str(user.id), str(project.id), asset_type=Asset.Type.IP_ADDRESS,
            environment=Asset.Environment.PRODUCTION, is_active=True,
            limit=2, offset=1,
        )

    assert [asset.name for asset in page] == ["target-3", "target-2"]
    select_statements = [q["sql"] for q in queries if q["sql"].lstrip().upper().startswith("SELECT")]
    assert len(select_statements) == 1
    assert "LIMIT 2 OFFSET 1" in select_statements[0].upper()
    assert "hidden" not in [asset.name for asset in page]


@pytest.mark.django_db(transaction=True)
def test_casefolded_search_preserves_json_tag_matching_and_pagination():
    user = User.objects.create_user(
        email="asset-tags-search@example.invalid", password="Strong-Test-Password-123!"
    )
    project = Project.objects.create(name="Tag Search", slug="tag-search-resource", owner=user)
    for i, tags in enumerate([["irrelevant"], ["STRASSE"], ["Straße"], ["strasse"]]):
        Asset.objects.create(
            project=project, owner=user, name=f"sample-{i}",
            slug=f"sample-{i}", type=Asset.Type.WEBSITE, tags=tags,
        )

    found = async_to_sync(_accessible_assets)(
        str(user.id), str(project.id), search="straße", limit=2, offset=1,
    )

    assert [asset.name for asset in found] == ["sample-2", "sample-1"]


@pytest.mark.django_db(transaction=True)
def test_listing_excludes_other_tenants_even_without_project_filter():
    owner = User.objects.create_user(
        email="asset-list-permitted@example.invalid", password="Strong-Test-Password-123!"
    )
    stranger = User.objects.create_user(
        email="asset-list-denied@example.invalid", password="Strong-Test-Password-123!"
    )
    good = Project.objects.create(name="My project", slug="asset-mine", owner=owner)
    bad = Project.objects.create(name="Their project", slug="asset-theirs", owner=stranger)
    Asset.objects.create(
        project=good, owner=owner, name="allowed", slug="allowed",
        type=Asset.Type.IP_ADDRESS,
    )
    Asset.objects.create(
        project=bad, owner=stranger, name="forbidden", slug="forbidden",
        type=Asset.Type.IP_ADDRESS,
    )

    result = async_to_sync(_accessible_assets)(str(owner.id), limit=5, offset=0)

    assert [asset.name for asset in result] == ["allowed"]


@pytest.mark.django_db(transaction=True)
def test_asset_list_and_detail_derive_scan_metadata_from_existing_scan_records():
    """Existing scans must appear in UI without rewriting historical production records."""
    from datetime import timedelta
    from django.utils import timezone
    from django_project.scans.models import Scan
    from fastapi_app.routers.assets import _asset_response, _get_asset

    owner = User.objects.create_user(email="asset-history-owner@example.invalid", password="Strong-Test-Password-123!")
    outsider = User.objects.create_user(email="asset-history-outsider@example.invalid", password="Strong-Test-Password-123!")
    project = Project.objects.create(name="Recorded scans", slug="recorded-scans", owner=owner)
    foreign_project = Project.objects.create(name="Other scans", slug="other-scans", owner=outsider)
    asset = Asset.objects.create(project=project, owner=owner, name="Audited target", slug="audited-target", type=Asset.Type.IP_ADDRESS)
    foreign_asset = Asset.objects.create(project=foreign_project, owner=outsider, name="Unrelated", slug="unrelated", type=Asset.Type.IP_ADDRESS)

    now = timezone.now()
    Scan.objects.create(project=project, asset=asset, name="Older scan", scan_type=Scan.Type.IP, status=Scan.Status.COMPLETED, started_at=now-timedelta(hours=2))
    Scan.objects.create(project=project, asset=asset, name="Recent scan", scan_type=Scan.Type.IP, status=Scan.Status.FAILED, started_at=now)
    Scan.objects.create(project=foreign_project, asset=foreign_asset, name="Foreign scan", scan_type=Scan.Type.IP, status=Scan.Status.COMPLETED, started_at=now)
    asset.refresh_from_db()
    assert asset.scan_count == 0 and asset.last_scanned_at is None  # historical stale denormalized fields

    with CaptureQueriesContext(connection) as queries:
        assets = async_to_sync(_accessible_assets)(str(owner.id), limit=10, offset=0)
    assert [str(a.id) for a in assets] == [str(asset.id)]
    assert len([q for q in queries if q["sql"].lstrip().upper().startswith("SELECT")]) == 1
    listed = _asset_response(assets[0])
    assert listed.scan_count == 2
    assert listed.last_scanned_at == now.isoformat()

    detailed = async_to_sync(_get_asset)(str(asset.id), str(owner.id))
    assert _asset_response(detailed).scan_count == 2
    assert _asset_response(detailed).last_scanned_at == now.isoformat()
    assert async_to_sync(_get_asset)(str(foreign_asset.id), str(owner.id)) is None
