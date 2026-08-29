from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()


class HasPermission(permissions.BasePermission):
    """Enforce permissions declared on a DRF view or viewset."""
    message = 'You do not have permission to perform this action.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        required = getattr(view, 'required_permissions', {})
        action = getattr(view, 'action', None) or request.method.lower()
        if isinstance(required, dict):
            perms = required.get(action, [])
        elif isinstance(required, str):
            perms = [required]
        elif isinstance(required, (list, tuple, set)):
            perms = list(required)
        else:
            perms = []
        if not perms:
            return True
        return request.user.has_any_permission(*perms)

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        action = getattr(view, 'action', None)
        if action in {'add_member', 'remove_member', 'update_member_role'}:
            return obj.memberships.filter(
                user=request.user,
                role__in=['owner', 'admin'],
            ).exists()
        return True


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.owner == request.user or request.user.is_superuser


class IsProjectMember(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return True
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(project_id=project_id, user=request.user).exists()


class IsProjectAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return True
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project_id=project_id,
            user=request.user,
            role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
        ).exists()


class IsTeamAdmin(permissions.BasePermission):
    """Only team owners/admins may manage team membership."""
    message = 'Only team owners or administrators may manage team membership.'

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        return obj.memberships.filter(
            user=request.user,
            role__in=['owner', 'admin'],
        ).exists()


class IsScanOwnerOrProjectMember(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or obj.initiated_by == request.user:
            return True
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(project=obj.project, user=request.user).exists()


class IsVulnerabilityAssigneeOrProjectMember(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser or obj.assigned_to == request.user:
            return True
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(project=obj.project, user=request.user).exists()
