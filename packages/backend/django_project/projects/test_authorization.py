from django.test import TestCase

from users.models import User

from .authorization import get_project_authorization
from .models import Project, ProjectMembership


class ProjectMembershipAuthorizationMatrixTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.test",
            password="Test-Owner-2026!",
            is_active=True,
        )
        self.admin = User.objects.create_user(
            email="admin@example.test",
            password="Test-Admin-2026!",
            is_active=True,
        )
        self.member = User.objects.create_user(
            email="member@example.test",
            password="Test-Member-2026!",
            is_active=True,
        )
        self.viewer = User.objects.create_user(
            email="viewer@example.test",
            password="Test-Viewer-2026!",
            is_active=True,
        )
        self.outsider = User.objects.create_user(
            email="outsider@example.test",
            password="Test-Outsider-2026!",
            is_active=True,
        )
        self.project = Project.objects.create(
            name="Authorization Matrix",
            slug="authorization-matrix",
            owner=self.owner,
        )
        self.owner_membership = ProjectMembership.objects.create(
            project=self.project,
            user=self.owner,
            role=ProjectMembership.Role.OWNER,
        )
        self.admin_membership = ProjectMembership.objects.create(
            project=self.project,
            user=self.admin,
            role=ProjectMembership.Role.ADMIN,
        )
        self.member_membership = ProjectMembership.objects.create(
            project=self.project,
            user=self.member,
            role=ProjectMembership.Role.MEMBER,
        )
        self.viewer_membership = ProjectMembership.objects.create(
            project=self.project,
            user=self.viewer,
            role=ProjectMembership.Role.VIEWER,
        )

    def test_read_matrix(self):
        for user in (self.owner, self.admin, self.member, self.viewer):
            self.assertTrue(get_project_authorization(self.project.pk, user).can_read)
        self.assertFalse(get_project_authorization(self.project.pk, self.outsider).can_read)

    def test_update_archive_and_member_management_matrix(self):
        for user in (self.owner, self.admin):
            authz = get_project_authorization(self.project.pk, user)
            self.assertTrue(authz.can_update)
            self.assertTrue(authz.can_archive)
            self.assertTrue(authz.can_manage_members)

        for user in (self.member, self.viewer, self.outsider):
            authz = get_project_authorization(self.project.pk, user)
            self.assertFalse(authz.can_update)
            self.assertFalse(authz.can_archive)
            self.assertFalse(authz.can_manage_members)

    def test_delete_is_owner_only(self):
        self.assertTrue(get_project_authorization(self.project.pk, self.owner).can_delete)
        for user in (self.admin, self.member, self.viewer, self.outsider):
            self.assertFalse(get_project_authorization(self.project.pk, user).can_delete)

    def test_admin_cannot_modify_owner_or_grant_owner_role(self):
        authz = get_project_authorization(self.project.pk, self.admin)
        self.assertFalse(authz.can_manage_membership(self.owner_membership))
        self.assertFalse(authz.can_change_role_to(ProjectMembership.Role.OWNER))
        self.assertTrue(authz.can_manage_membership(self.member_membership, new_role=ProjectMembership.Role.VIEWER))

    def test_owner_can_manage_all_members_and_roles(self):
        authz = get_project_authorization(self.project.pk, self.owner)
        self.assertTrue(authz.can_manage_membership(self.admin_membership, new_role=ProjectMembership.Role.MEMBER))
        self.assertTrue(authz.can_manage_membership(self.owner_membership))
        self.assertTrue(authz.can_change_role_to(ProjectMembership.Role.OWNER))
