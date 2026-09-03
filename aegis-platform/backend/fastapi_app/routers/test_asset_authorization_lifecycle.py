from datetime import timedelta
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase
from django.utils import timezone
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.main import app
from fastapi_app.routers import assets as assets_router


class AssetAuthorizationLifecycleTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.user = User.objects.create_user(email=f"authorization-lifecycle-{uuid4()}@example.invalid", password="Strong-Test-Password-123!", first_name="Authorization", last_name="Lifecycle")
        self.project = Project.objects.create(name="Authorization Lifecycle", slug=f"authorization-lifecycle-{uuid4()}", owner=self.user)
        self.asset = Asset.objects.create(project=self.project, name="lifecycle-target", slug=f"lifecycle-target-{uuid4()}", type=Asset.Type.IP_ADDRESS, configuration={"host": "10.0.0.10", "authorized": True}, owner=self.user)

    def test_authorization_record_survives_asset_deletion_with_identity_snapshot(self):
        decision = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", reason="explicit authorization")
        asset_id = self.asset.id
        self.asset.delete()
        decision.refresh_from_db()
        self.assertIsNone(decision.asset_id)
        self.assertEqual(decision.asset_identity_snapshot, asset_id)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.target_snapshot, "10.0.0.10")

    def test_authorization_record_remains_immutable_after_asset_deletion(self):
        decision = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", reason="explicit authorization")
        self.asset.delete()
        with self.assertRaises(ValidationError): decision.save()
        with self.assertRaises(ValidationError): decision.delete()

    def test_latest_decision_is_deterministic_and_lineage_is_explicit(self):
        first = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", reason="open")
        second = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=False, target_snapshot="10.0.0.10", reason="closed", supersedes=first)
        latest = AssetAuthorization.objects.filter(asset=self.asset).order_by("-created_at", "-id").first()
        self.assertEqual(latest.id, second.id)
        self.assertEqual(second.supersedes_id, first.id)
        self.assertEqual(second.asset_identity_snapshot, self.asset.id)

    def test_instance_and_bulk_orm_mutation_are_blocked(self):
        decision = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10")
        decision.authorized = False
        with self.assertRaises(ValidationError): decision.save()
        with self.assertRaises(ValidationError): AssetAuthorization.objects.filter(pk=decision.pk).update(authorized=False)
        with self.assertRaises(ValidationError): AssetAuthorization.objects.filter(pk=decision.pk).delete()

    def test_expired_authorization_is_invalid(self):
        decision = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", expires_at=timezone.now() - timedelta(seconds=1))
        self.assertFalse(decision.is_currently_valid)

    def test_correlation_id_makes_endpoint_idempotent(self):
        correlation_id = uuid4()
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                payload = {"authorized": True, "reason": "approved window", "correlation_id": str(correlation_id)}
                first = client.post(f"/assets/{self.asset.id}/authorization", json=payload)
                second = client.post(f"/assets/{self.asset.id}/authorization", json=payload)
            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 200)
            self.assertEqual(AssetAuthorization.objects.filter(correlation_id=correlation_id).count(), 1)
        finally:
            app.dependency_overrides.clear()

    def test_correlation_id_cannot_be_reused_for_a_different_decision(self):
        correlation_id = uuid4()
        AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", correlation_id=correlation_id)
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                response = client.post(f"/assets/{self.asset.id}/authorization", json={"authorized": False, "reason": "conflicting reuse", "correlation_id": str(correlation_id)})
            self.assertEqual(response.status_code, 409)
        finally:
            app.dependency_overrides.clear()
