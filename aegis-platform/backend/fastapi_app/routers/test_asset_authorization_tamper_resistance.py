from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User

pytestmark = pytest.mark.django_db(transaction=True)


def _fixture():
    owner = User.objects.create_user(
        email="authorization-tamper-owner@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Authorization Tamper Resistance Regression",
        slug="authorization-tamper-resistance-regression",
        owner=owner,
    )
    asset = Asset.objects.create(
        project=project,
        name="tamper-target",
        slug="tamper-target",
        type=Asset.Type.IP_ADDRESS,
        configuration={"host": "tamper-target"},
        owner=owner,
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=owner,
        authorized=True,
        target_snapshot="tamper-target",
        reason="approved",
    )
    return decision


def test_authorization_queryset_update_is_blocked():
    decision = _fixture()
    with pytest.raises(ValidationError, match="bulk updates are forbidden"):
        AssetAuthorization.objects.filter(pk=decision.pk).update(authorized=False)
    assert AssetAuthorization.objects.get(pk=decision.pk).authorized is True


def test_authorization_queryset_delete_is_blocked():
    decision = _fixture()
    with pytest.raises(ValidationError, match="bulk deletes are forbidden"):
        AssetAuthorization.objects.filter(pk=decision.pk).delete()
    assert AssetAuthorization.objects.filter(pk=decision.pk).exists()


def test_authorization_bulk_update_is_blocked():
    decision = _fixture()
    decision.authorized = False
    with pytest.raises(ValidationError, match="bulk updates are forbidden"):
        AssetAuthorization.objects.bulk_update([decision], ["authorized"])
    assert AssetAuthorization.objects.get(pk=decision.pk).authorized is True
