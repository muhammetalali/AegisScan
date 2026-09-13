from __future__ import annotations

import pytest

from django_project.assets.models import Asset, AssetAuthorization, TechnologyFingerprint
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.services.wstg_execution_planner import plan_wstg_for_authorized_asset


@pytest.mark.django_db
def test_persisted_asset_authorization_and_flash_fingerprint_drive_wstg_plan():
    user = User.objects.create_user(
        email='wstg-planner-persistence@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Planner Persistence',
        slug='wstg-planner-persistence',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized Website',
        slug='authorized-website',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://planner.example.invalid'},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='https://planner.example.invalid',
        reason='WSTG planner persistence proof',
    )
    fingerprint = TechnologyFingerprint.objects.create(
        asset=asset,
        name='Adobe Flash Player',
        version='32',
        category='client-runtime',
        confidence=0.99,
        source='wstg-planner-reality',
        evidence='Persisted technology fingerprint for planner contract proof.',
    )

    result = plan_wstg_for_authorized_asset(
        project_id=str(project.id),
        asset_id=str(asset.id),
        depth='comprehensive',
    )

    assert result.asset_ref == str(asset.id)
    assert result.authorization_ref == str(authorization.id)
    assert len(result.items) == 97
    flash = next(item for item in result.items if item.wstg_id == 'WSTG-v42-CLNT-08')
    assert flash.status == 'planned'
    assert 'browser.spa-discovery' in flash.provider_capability_ids
    assert f'technology:{fingerprint.id}' in flash.applicability_evidence_refs
    assert f'authorization:{authorization.id}' in flash.applicability_evidence_refs


@pytest.mark.django_db
def test_persisted_planner_fails_closed_after_authorization_revocation():
    user = User.objects.create_user(
        email='wstg-planner-revoked@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Planner Revoked',
        slug='wstg-planner-revoked',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Revoked Website',
        slug='revoked-website',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://revoked-planner.example.invalid'},
    )
    granted = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='https://revoked-planner.example.invalid',
        reason='initial grant',
    )
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot='https://revoked-planner.example.invalid',
        reason='revoked before planning',
        supersedes=granted,
    )

    with pytest.raises(PermissionError, match='not currently valid'):
        plan_wstg_for_authorized_asset(
            project_id=str(project.id),
            asset_id=str(asset.id),
            depth='standard',
        )
