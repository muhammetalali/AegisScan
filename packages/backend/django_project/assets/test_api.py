from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from audit.models import AuditLog
from audit.services import verify_audit_chain
from projects.models import Project, ProjectMembership
from users.models import User, UserRole

from .models import Asset, AssetRelationship, TechnologyFingerprint


class AssetsApiTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="assets-owner@test.local",
            password="AssetsOwner-2026!",
            role=UserRole.SECURITY_MANAGER,
            is_active=True,
            is_verified=True,
        )
        self.viewer = User.objects.create_user(
            email="assets-viewer@test.local",
            password="AssetsViewer-2026!",
            role=UserRole.VIEWER,
            is_active=True,
            is_verified=True,
        )
        self.admin = User.objects.create_user(
            email="assets-admin@test.local",
            password="AssetsAdmin-2026!",
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
        )
        self.outsider = User.objects.create_user(
            email="assets-outsider@test.local",
            password="AssetsOutsider-2026!",
            role=UserRole.VIEWER,
            is_active=True,
            is_verified=True,
        )
        self.project = Project.objects.create(
            name="Assets API Project",
            slug="assets-api-project",
            owner=self.owner,
            environment=Project.Environment.DEVELOPMENT,
        )
        ProjectMembership.objects.create(project=self.project, user=self.owner, role=ProjectMembership.Role.OWNER)
        ProjectMembership.objects.create(project=self.project, user=self.viewer, role=ProjectMembership.Role.VIEWER)
        self.other_project = Project.objects.create(
            name="Other Assets Project",
            slug="other-assets-project",
            owner=self.admin,
            environment=Project.Environment.DEVELOPMENT,
        )
        ProjectMembership.objects.create(project=self.other_project, user=self.admin, role=ProjectMembership.Role.OWNER)

    def asset_payload(self, project=None, name="Primary Website"):
        return {
            "project": str((project or self.project).pk),
            "name": name,
            "type": "website",
            "description": "Asset under API authorization test",
            "environment": "development",
            "criticality": "medium",
            "configuration": {"url": "https://example.test"},
            "tags": ["e2e", "assets"],
            "metadata": {},
            "is_active": True,
        }

    def create_asset(self, user=None, project=None, name="Primary Website"):
        self.client.force_authenticate(user=user or self.owner)
        response = self.client.post(
            reverse("asset-list"),
            self.asset_payload(project=project, name=name),
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        return Asset.objects.get(pk=response.data["id"])

    def test_owner_can_create_and_audit_asset(self):
        asset = self.create_asset()
        self.assertEqual(asset.owner_id, self.owner.pk)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.ASSET_CREATE,
                resource_type="Asset",
                resource_id=str(asset.pk),
            ).exists()
        )
        self.assertTrue(verify_audit_chain())

    def test_viewer_can_read_but_cannot_create_update_or_delete(self):
        asset = self.create_asset()
        self.client.force_authenticate(user=self.viewer)

        detail_url = reverse("asset-detail", args=[asset.pk])
        list_response = self.client.get(reverse("asset-list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data["results"]), 1)

        self.assertEqual(self.client.get(detail_url).status_code, status.HTTP_200_OK)
        update_response = self.client.patch(detail_url, {"description": "forbidden"}, format="json")
        self.assertEqual(update_response.status_code, status.HTTP_403_FORBIDDEN)
        delete_response = self.client.delete(detail_url)
        self.assertEqual(delete_response.status_code, status.HTTP_403_FORBIDDEN)

        create_response = self.client.post(
            reverse("asset-list"),
            self.asset_payload(name="Viewer Must Not Create"),
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(Asset.objects.filter(name="Viewer Must Not Create").exists())

    def test_outsider_is_isolated(self):
        asset = self.create_asset()
        self.client.force_authenticate(user=self.outsider)
        self.assertEqual(
            self.client.get(reverse("asset-detail", args=[asset.pk])).status_code,
            status.HTTP_404_NOT_FOUND,
        )
        response = self.client.get(reverse("asset-list"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["results"], [])

    def test_duplicate_slug_is_scoped_to_project(self):
        first = self.create_asset(name="Duplicate Name")
        second = self.create_asset(name="Duplicate Name")
        self.assertNotEqual(first.slug, second.slug)
        other = self.create_asset(user=self.admin, project=self.other_project, name="Duplicate Name")
        self.assertEqual(first.slug, other.slug)

    def test_asset_update_is_audited(self):
        asset = self.create_asset()
        self.client.force_authenticate(user=self.owner)
        response = self.client.patch(
            reverse("asset-detail", args=[asset.pk]),
            {"description": "updated", "criticality": "high"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.ASSET_UPDATE,
                resource_id=str(asset.pk),
            ).exists()
        )

    def test_security_manager_without_asset_delete_cannot_delete(self):
        asset = self.create_asset()
        self.client.force_authenticate(user=self.owner)
        response = self.client.delete(reverse("asset-detail", args=[asset.pk]))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(Asset.objects.filter(pk=asset.pk).exists())

    def test_admin_can_delete_and_delete_is_audited(self):
        asset = self.create_asset()
        ProjectMembership.objects.create(project=self.project, user=self.admin, role=ProjectMembership.Role.ADMIN)
        self.client.force_authenticate(user=self.admin)
        response = self.client.delete(reverse("asset-detail", args=[asset.pk]))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Asset.objects.filter(pk=asset.pk).exists())
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.ASSET_DELETE,
                resource_id=str(asset.pk),
            ).exists()
        )

    def test_relationship_requires_same_project(self):
        source = self.create_asset(name="Source")
        target = self.create_asset(name="Target")
        other = self.create_asset(user=self.admin, project=self.other_project, name="Other Target")
        self.client.force_authenticate(user=self.owner)

        valid = self.client.post(
            reverse("asset-relationship-list"),
            {"source": str(source.pk), "target": str(target.pk), "relationship_type": "depends_on", "metadata": {}},
            format="json",
        )
        self.assertEqual(valid.status_code, status.HTTP_201_CREATED, valid.data)

        invalid = self.client.post(
            reverse("asset-relationship-list"),
            {"source": str(source.pk), "target": str(other.pk), "relationship_type": "depends_on", "metadata": {}},
            format="json",
        )
        self.assertEqual(invalid.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(AssetRelationship.objects.filter(source=source).count(), 1)

    def test_relationship_mutation_is_authorized_and_audited(self):
        source = self.create_asset(name="Source")
        target = self.create_asset(name="Target")
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            reverse("asset-relationship-list"),
            {"source": str(source.pk), "target": str(target.pk), "relationship_type": "depends_on", "metadata": {}},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        relationship = AssetRelationship.objects.get(pk=response.data["id"])
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.ASSET_RELATIONSHIP_CREATE,
                resource_id=str(relationship.pk),
            ).exists()
        )

        self.client.force_authenticate(user=self.viewer)
        denied = self.client.delete(reverse("asset-relationship-detail", args=[relationship.pk]))
        self.assertEqual(denied.status_code, status.HTTP_403_FORBIDDEN)

    def test_technology_fingerprint_mutation_is_authorized_and_audited(self):
        asset = self.create_asset()
        other = self.create_asset(user=self.admin, project=self.other_project, name="Other Asset")
        self.client.force_authenticate(user=self.owner)
        response = self.client.post(
            reverse("technology-list"),
            {
                "asset": str(asset.pk),
                "name": "Django",
                "version": "5.2",
                "category": "framework",
                "confidence": 0.98,
                "source": "header",
                "evidence": "X-Powered-By",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        technology = TechnologyFingerprint.objects.get(pk=response.data["id"])
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.ASSET_TECHNOLOGY_CREATE,
                resource_id=str(technology.pk),
            ).exists()
        )

        move_response = self.client.patch(
            reverse("technology-detail", args=[technology.pk]),
            {"asset": str(other.pk)},
            format="json",
        )
        self.assertEqual(move_response.status_code, status.HTTP_403_FORBIDDEN)
        technology.refresh_from_db()
        self.assertEqual(technology.asset_id, asset.pk)

    def test_viewer_cannot_mutate_relationship_or_technology(self):
        source = self.create_asset(name="Source")
        target = self.create_asset(name="Target")
        self.client.force_authenticate(user=self.owner)
        relationship_response = self.client.post(
            reverse("asset-relationship-list"),
            {"source": str(source.pk), "target": str(target.pk), "relationship_type": "contains", "metadata": {}},
            format="json",
        )
        relationship = AssetRelationship.objects.get(pk=relationship_response.data["id"])
        technology_response = self.client.post(
            reverse("technology-list"),
            {
                "asset": str(source.pk),
                "name": "Nginx",
                "version": "1.27",
                "category": "server",
                "confidence": 0.9,
                "source": "header",
                "evidence": "Server: nginx",
            },
            format="json",
        )
        technology = TechnologyFingerprint.objects.get(pk=technology_response.data["id"])

        self.client.force_authenticate(user=self.viewer)
        self.assertEqual(
            self.client.delete(reverse("asset-relationship-detail", args=[relationship.pk])).status_code,
            status.HTTP_403_FORBIDDEN,
        )
        self.assertEqual(
            self.client.delete(reverse("technology-detail", args=[technology.pk])).status_code,
            status.HTTP_403_FORBIDDEN,
        )
