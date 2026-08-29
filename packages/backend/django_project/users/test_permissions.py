from django.test import TestCase
from rest_framework.test import APIRequestFactory

from .models import Team, TeamMembership, User
from .permissions import HasPermission


class HasPermissionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            email="analyst@example.com",
            password="Password123!",
            first_name="Security",
            last_name="Analyst",
            role="security_analyst",
        )
        self.team = Team.objects.create(name="Security Team", owner=self.user)
        TeamMembership.objects.create(team=self.team, user=self.user, role=TeamMembership.Role.MEMBER)

    def test_action_list_permission_declaration_is_supported(self):
        request = self.factory.post("/users/1/activate/")
        request.user = self.user

        class View:
            action = "activate"
            required_permissions = ["user.update"]

        self.assertTrue(HasPermission().has_permission(request, View()))

    def test_normal_team_member_cannot_manage_members(self):
        request = self.factory.post(f"/teams/{self.team.pk}/add_member/")
        request.user = self.user

        class View:
            action = "add_member"

        self.assertFalse(HasPermission().has_object_permission(request, View(), self.team))

    def test_team_admin_can_manage_members(self):
        membership = self.team.memberships.get(user=self.user)
        membership.role = TeamMembership.Role.ADMIN
        membership.save(update_fields=["role"])

        request = self.factory.post(f"/teams/{self.team.pk}/add_member/")
        request.user = self.user

        class View:
            action = "add_member"

        self.assertTrue(HasPermission().has_object_permission(request, View(), self.team))
