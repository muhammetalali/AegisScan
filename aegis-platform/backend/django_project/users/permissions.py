from collections.abc import Mapping

from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()


class HasPermission(permissions.BasePermission):
    """
    Enforce the permission contract declared by a DRF ViewSet/action.

    ``@action`` can override ``required_permissions`` with a list/string while
    the ViewSet normally declares a mapping. Normalize all supported forms so
    custom actions cannot crash or accidentally bypass authorization.
    Missing declarations fail closed.
    """
    message = 'You do not have permission to perform this action.'

    @staticmethod
    def _required_permissions(view, action):
        declared = getattr(view, 'required_permissions', None)

        if declared is None:
            return ()
        if isinstance(declared, str):
            return (declared,)
        if isinstance(declared, Mapping):
            declared = declared.get(action, ())
            if isinstance(declared, str):
                return (declared,)
        if isinstance(declared, (list, tuple, set, frozenset)):
            return tuple(permission for permission in declared if isinstance(permission, str) and permission)
        return ()

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        action = getattr(view, 'action', None) or request.method.lower()
        required_permissions = self._required_permissions(view, action)

        # Authorization must never silently succeed when an endpoint has no
        # declared permission contract.
        if not required_permissions:
            return False

        return request.user.has_any_permission(*required_permissions)

    def has_object_permission(self, request, view, obj):
        # Querysets are responsible for tenant/object scoping. This permission
        # class only enforces the declared capability; object scope is enforced
        # by get_queryset/get_object and dedicated object permissions.
        return True


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Object-level permission to only allow owners to edit an object."""
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.owner == request.user or request.user.is_superuser


class IsProjectMember(permissions.BasePermission):
    """Check if the authenticated user belongs to the requested project."""
    message = 'You are not a member of this project.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return False

        from django_project.projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project_id=project_id,
            user=request.user,
        ).exists()


class IsProjectAdmin(permissions.BasePermission):
    """Check if user is an admin/owner of the requested project."""
    message = 'You must be a project owner or admin.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return False

        from django_project.projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project_id=project_id,
            user=request.user,
            role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
        ).exists()


class IsTeamAdmin(permissions.BasePermission):
    """Allow only team owners/admins to mutate team membership."""
    message = 'You must be a team owner or admin to manage team membership.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True

        team_id = view.kwargs.get('pk') or view.kwargs.get('team_pk')
        if not team_id:
            return False

        from .models import TeamMembership
        return TeamMembership.objects.filter(
            team_id=team_id,
            user=request.user,
            role__in=[TeamMembership.Role.OWNER, TeamMembership.Role.ADMIN],
        ).exists()


class IsScanOwnerOrProjectMember(permissions.BasePermission):
    """Check if user owns the scan or is a project member."""
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if obj.initiated_by == request.user:
            return True
        from django_project.projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project=obj.project,
            user=request.user,
        ).exists()


class IsVulnerabilityAssigneeOrProjectMember(permissions.BasePermission):
    """Check if user is assigned to vulnerability or is a project member."""
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        if obj.assigned_to == request.user:
            return True
        from django_project.projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project=obj.project,
            user=request.user,
        ).exists()
