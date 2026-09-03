from django.core.exceptions import ValidationError
from django.test import TestCase

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User


class AssetAuthorizationLifecycleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="authorization-lifecycle@example.invalid",
            password="Strong-Test-Password-123!",
            first_name="Authorization",
            last_name="Lifecycle",
        )
        self.project = Project.objects.create(
            name="Authorization Lifecycle",
            slug="authorization-lifecycle",
            owner=self.user,
        )
        self.asset = Asset.objects.create(
            project=self.project,
            name="lifecycle-target",
            slug="lifecycle-target",
            type=Asset.Type.IP_ADDRESS,
            configuration={"host": "10.0.0.10", "authorized": True},
            owner=self.user,
        )

    def test_authorization_record_survives_asset_deletion_with_identity_snapshot(self):
        decision = AssetAuthorization.objects.create(
            asset=self.asset,
            actor=self.user,
            authorized=True,
            target_snapshot="10.0.0.10",
            reason="explicit authorization",
        )
        asset_id = self.asset.id

        self.asset.delete()

        decision.refresh_from_db()
        self.assertIsNone(decision.asset_id)
        self.assertEqual(decision.asset_identity_snapshot, asset_id)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.target_snapshot, "10.0.0.10")

    def test_authorization_record_remains_immutable_after_asset_deletion(self):
        decision = AssetAuthorization.objects.create(
            asset=self.asset,
            actor=self.user,
            authorized=True,
            target_snapshot="10.0.0.10",
            reason="explicit authorization",
        )
        self.asset.delete()

        with self.assertRaises(ValidationError):
            decision.save()
        with self.assertRaises(ValidationError):
            decision.delete()
