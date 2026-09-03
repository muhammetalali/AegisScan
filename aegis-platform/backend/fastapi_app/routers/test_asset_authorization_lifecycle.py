from datetime import timedelta
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase
from django.utils import timezone
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
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
            self.assertEqual(AuditLog.objects.filter(resource_type="AssetAuthorization", action="asset_authorization_grant", resource_id__isnull=False).count(), 1)
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

    def test_request_identity_and_audit_linkage_are_persisted_atomically(self):
        correlation_id = uuid4()
        request_id = uuid4()
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/assets/{self.asset.id}/authorization",
                    json={"authorized": True, "reason": "governance approval", "correlation_id": str(correlation_id)},
                    headers={"X-Request-ID": str(request_id), "User-Agent": "AegisScan-Test/1.0"},
                )
            self.assertEqual(response.status_code, 200)
            decision = AssetAuthorization.objects.get(correlation_id=correlation_id)
            audit = AuditLog.objects.get(resource_type="AssetAuthorization", resource_id=str(decision.id))
            self.assertEqual(decision.request_id, request_id)
            self.assertEqual(audit.request_id, request_id)
            self.assertEqual(audit.user_id, self.user.id)
            self.assertEqual(audit.metadata["correlation_id"], str(correlation_id))
            self.assertEqual(audit.metadata["request_id"], str(request_id))
            self.assertEqual(audit.metadata["asset_id"], str(self.asset.id))
            self.assertEqual(audit.resource_id, str(decision.id))
        finally:
            app.dependency_overrides.clear()

    def test_invalid_request_identity_is_rejected_before_persistence(self):
        correlation_id = uuid4()
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                response = client.post(
                    f"/assets/{self.asset.id}/authorization",
                    json={"authorized": True, "reason": "invalid request id", "correlation_id": str(correlation_id)},
                    headers={"X-Request-ID": "not-a-uuid"},
                )
            self.assertEqual(response.status_code, 422)
            self.assertFalse(AssetAuthorization.objects.filter(correlation_id=correlation_id).exists())
            self.assertFalse(AuditLog.objects.filter(resource_type="AssetAuthorization").exists())
        finally:
            app.dependency_overrides.clear()

    def test_idempotent_retry_with_new_http_request_id_does_not_duplicate_audit(self):
        correlation_id = uuid4()
        first_request_id = uuid4()
        retry_request_id = uuid4()
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                payload = {"authorized": True, "reason": "retry-safe approval", "correlation_id": str(correlation_id)}
                first = client.post(f"/assets/{self.asset.id}/authorization", json=payload, headers={"X-Request-ID": str(first_request_id)})
                retry = client.post(f"/assets/{self.asset.id}/authorization", json=payload, headers={"X-Request-ID": str(retry_request_id)})
            self.assertEqual(first.status_code, 200)
            self.assertEqual(retry.status_code, 200)
            decision = AssetAuthorization.objects.get(correlation_id=correlation_id)
            self.assertEqual(decision.request_id, first_request_id)
            self.assertEqual(AuditLog.objects.filter(resource_type="AssetAuthorization", resource_id=str(decision.id)).count(), 1)
            self.assertFalse(AssetAuthorization.objects.filter(request_id=retry_request_id).exists())
        finally:
            app.dependency_overrides.clear()

    def test_configuration_change_revocation_is_audited_with_same_request_identity(self):
        initial = AssetAuthorization.objects.create(asset=self.asset, actor=self.user, authorized=True, target_snapshot="10.0.0.10", reason="initial authorization")
        request_id = uuid4()
        app.dependency_overrides[assets_router.get_current_user] = lambda: {"user_id": str(self.user.id), "is_staff": False}
        try:
            with TestClient(app) as client:
                response = client.patch(
                    f"/assets/{self.asset.id}",
                    json={"configuration": {"host": "10.0.0.11"}},
                    headers={"X-Request-ID": str(request_id), "User-Agent": "AegisScan-Test/1.0"},
                )
            self.assertEqual(response.status_code, 200)
            decision = AssetAuthorization.objects.filter(asset=self.asset).order_by("-created_at", "-id").first()
            self.assertFalse(decision.authorized)
            self.assertEqual(decision.supersedes_id, initial.id)
            self.assertEqual(decision.request_id, request_id)
            audit = AuditLog.objects.get(resource_type="AssetAuthorization", resource_id=str(decision.id))
            self.assertEqual(audit.request_id, request_id)
            self.assertEqual(audit.metadata["trigger"], "asset_configuration_change")
            self.assertEqual(audit.metadata["request_id"], str(request_id))
        finally:
            app.dependency_overrides.clear()
