from django.urls import reverse
from rest_framework.test import APITestCase

from audit.models import AuditLog
from users.models import User, UserRole

from .models import Project, ProjectMembership


class ProjectsAPITests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="project-owner@example.test",
            password="Owner-2026!",
            role=UserRole.SECURITY_MANAGER,
            is_active=True,
        )
        self.admin = User.objects.create_user(email="project-admin@example.test", password="Admin-2026!", is_active=True)
        self.member = User.objects.create_user(email="project-member@example.test", password="Member-2026!", is_active=True)
        self.viewer = User.objects.create_user(email="project-viewer@example.test", password="Viewer-2026!", is_active=True)
        self.outsider = User.objects.create_user(email="project-outsider@example.test", password="Outsider-2026!", is_active=True)
        self.project = Project.objects.create(name="API Project", slug="api-project", owner=self.owner)
        ProjectMembership.objects.create(project=self.project, user=self.owner, role=ProjectMembership.Role.OWNER)
        ProjectMembership.objects.create(project=self.project, user=self.admin, role=ProjectMembership.Role.ADMIN)
        ProjectMembership.objects.create(project=self.project, user=self.member, role=ProjectMembership.Role.MEMBER)

    def test_owner_can_create_and_audit_project(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(reverse("project-list"), {"name": "Created", "slug": "created-project"}, format="json")
        self.assertEqual(response.status_code, 201)
        created = Project.objects.get(slug="created-project")
        self.assertTrue(ProjectMembership.objects.filter(project=created, user=self.owner, role=ProjectMembership.Role.OWNER).exists())
        self.assertTrue(AuditLog.objects.filter(action=AuditLog.Action.PROJECT_CREATE, resource_id=str(created.pk)).exists())

    def test_viewer_cannot_create_project(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post(reverse("project-list"), {"name": "Denied", "slug": "denied-project"}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Project.objects.filter(slug="denied-project").exists())

    def test_queryset_is_project_scoped(self):
        self.client.force_authenticate(self.outsider)
        response = self.client.get(reverse("project-list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 0)

    def test_admin_can_update_and_archive_but_not_delete(self):
        self.client.force_authenticate(self.admin)
        response = self.client.patch(reverse("project-detail", args=[self.project.pk]), {"name": "Updated"}, format="json")
        self.assertEqual(response.status_code, 200)
        archive = self.client.post(reverse("project-archive", args=[self.project.pk]))
        self.assertEqual(archive.status_code, 200)
        delete = self.client.delete(reverse("project-detail", args=[self.project.pk]))
        self.assertEqual(delete.status_code, 403)

    def test_member_cannot_mutate_project(self):
        self.client.force_authenticate(self.member)
        response = self.client.patch(reverse("project-detail", args=[self.project.pk]), {"name": "Denied"}, format="json")
        self.assertEqual(response.status_code, 403)

    def test_admin_cannot_grant_owner(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            reverse("project-members", args=[self.project.pk]),
            {"email": self.outsider.email, "role": ProjectMembership.Role.OWNER},
            format="json",
        )
        self.assertEqual(response.status_code, 403)
