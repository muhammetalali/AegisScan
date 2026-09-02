import pytest
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory, force_authenticate

from django_project.users.models import Team, TeamMembership, User, UserRole
from django_project.users.permissions import HasPermission, IsProjectAdmin, IsProjectMember, IsTeamAdmin
from django_project.users.views import TeamViewSet
from django_project.projects.models import Project, ProjectMembership


class PermissionView:
    action = 'update'
    required_permissions = {'update': 'user.update'}


class ListPermissionView:
    action = 'custom'
    required_permissions = ['user.update']


@pytest.mark.django_db
def test_has_permission_accepts_mapping_and_string():
    user = User.objects.create_user(
        email='permission-admin@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Permission',
        last_name='Admin',
        role=UserRole.ADMIN,
    )
    request = APIRequestFactory().get('/api/v1/users/')
    force_authenticate(request, user=user)
    request = Request(request)

    permission = HasPermission()
    assert permission.has_permission(request, PermissionView()) is True


@pytest.mark.django_db
def test_has_permission_accepts_action_level_list_without_crashing():
    user = User.objects.create_user(
        email='permission-action@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Permission',
        last_name='Action',
        role=UserRole.ADMIN,
    )
    request = APIRequestFactory().post('/api/v1/users/1/activate/')
    force_authenticate(request, user=user)
    request = Request(request)

    permission = HasPermission()
    assert permission.has_permission(request, ListPermissionView()) is True


@pytest.mark.django_db
def test_has_permission_fails_closed_without_contract():
    user = User.objects.create_user(
        email='permission-closed@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Permission',
        last_name='Closed',
        role=UserRole.ADMIN,
    )
    request = APIRequestFactory().get('/api/v1/unknown/')
    force_authenticate(request, user=user)
    request = Request(request)

    class UnconfiguredView:
        action = 'list'

    assert HasPermission().has_permission(request, UnconfiguredView()) is False


@pytest.mark.django_db
def test_project_permissions_fail_closed_without_project_scope():
    user = User.objects.create_user(
        email='project-scope@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Project',
        last_name='Scope',
    )
    request = APIRequestFactory().post('/api/v1/projects/')
    force_authenticate(request, user=user)
    request = Request(request)

    class UnscopedView:
        kwargs = {}

    assert IsProjectMember().has_permission(request, UnscopedView()) is False
    assert IsProjectAdmin().has_permission(request, UnscopedView()) is False


@pytest.mark.django_db
def test_team_queryset_isolation_and_team_admin_gate():
    owner = User.objects.create_user(
        email='team-owner@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Team',
        last_name='Owner',
        role=UserRole.ADMIN,
    )
    member = User.objects.create_user(
        email='team-member@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Team',
        last_name='Member',
        role=UserRole.ADMIN,
    )
    outsider = User.objects.create_user(
        email='team-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Team',
        last_name='Outsider',
        role=UserRole.ADMIN,
    )

    team = Team.objects.create(name='Scoped Team', owner=owner)
    TeamMembership.objects.create(team=team, user=owner, role=TeamMembership.Role.OWNER)
    TeamMembership.objects.create(team=team, user=member, role=TeamMembership.Role.MEMBER)

    factory = APIRequestFactory()
    request = factory.get(f'/api/v1/teams/{team.pk}/')
    force_authenticate(request, user=outsider)
    request = Request(request)
    view = TeamViewSet()
    view.request = request

    assert not view.get_queryset().filter(pk=team.pk).exists()
    assert IsTeamAdmin().has_permission(request, type('V', (), {'kwargs': {'pk': str(team.pk)}})()) is False

    request = factory.get(f'/api/v1/teams/{team.pk}/')
    force_authenticate(request, user=owner)
    request = Request(request)
    view.request = request
    assert view.get_queryset().filter(pk=team.pk).exists()
    assert IsTeamAdmin().has_permission(request, type('V', (), {'kwargs': {'pk': str(team.pk)}})()) is True


@pytest.mark.django_db
def test_project_membership_is_tenant_boundary():
    owner = User.objects.create_user(
        email='tenant-owner@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Tenant',
        last_name='Owner',
    )
    outsider = User.objects.create_user(
        email='tenant-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Tenant',
        last_name='Outsider',
    )
    project = Project.objects.create(name='Tenant Project', slug='tenant-project', owner=owner)
    ProjectMembership.objects.create(project=project, user=owner, role=ProjectMembership.Role.OWNER)

    factory = APIRequestFactory()
    request = factory.get(f'/api/v1/projects/{project.pk}/')
    force_authenticate(request, user=outsider)
    request = Request(request)
    view = type('V', (), {'kwargs': {'project_pk': str(project.pk)}})()

    assert IsProjectMember().has_permission(request, view) is False
    assert IsProjectAdmin().has_permission(request, view) is False
