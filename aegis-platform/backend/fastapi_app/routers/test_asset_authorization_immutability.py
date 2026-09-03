from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User

pytestmark = pytest.mark.django_db(transaction=True)


def _fixture():
    owner = User.objects.create_user(
        email="authorization-immutability-owner@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Authorization Immutability Regression",
        slug="authorization-immutability-regression",
        owner=owner,
    )
    asset = Asset.objects.create(
        project=project,
        name="immutable-target",
        slug="immutable-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "immutable-target"},
        owner=owner,
    )
    return owner, asset


def test_authorization_decision_cannot_be_updated_in_place():
    owner, asset = _fixture()
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=True,
        target_snapshot="immutable-target",
        reason="approved",
    )

    decision.authorized = False
    with pytest.raises(ValidationError, match="immutable"):
        decision.save()

    persisted = AssetAuthorization.objects.get(pk=decision.pk)
    assert persisted.authorized is True
    assert persisted.reason == "approved"


def test_authorization_decision_cannot_be_deleted():
    owner, asset = _fixture()
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=False,
        target_snapshot="immutable-target",
        reason="revoked",
    )

    with pytest.raises(ValidationError, match="cannot be deleted"):
        decision.delete()

    assert AssetAuthorization.objects.filter(pk=decision.pk).exists()
