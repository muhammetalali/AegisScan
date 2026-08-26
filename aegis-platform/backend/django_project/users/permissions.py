from rest_framework import permissions
from django.contrib.auth import get_user_model

User = get_user_model()


class HasPermission(permissions.BasePermission):
    """
    Check if user has required permission based on role.
    """
    message = 'You do not have permission to perform this action.'

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Superuser has all permissions
        if request.user.is_superuser:
            return True

        # Get required permissions for this action
        required_permissions = getattr(view, 'required_permissions', {})
        action = view.action if hasattr(view, 'action') else request.method.lower()
        perms = required_permissions.get(action, [])

        if isinstance(perms, str):
            perms = [perms]

        # Check if user has any of the required permissions
        return request.user.has_any_permission(*perms)

    def has_object_permission(self, request, view, obj):
        # Check object-level permissions if needed
        return True


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner
        return obj.owner == request.user or request.user.is_superuser


class IsProjectMember(permissions.BasePermission):
    """
    Check if user is a member of the project.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return True  # Let object-level permission handle it

        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project_id=project_id,
            user=request.user
        ).exists()


class IsProjectAdmin(permissions.BasePermission):
    """
    Check if user is admin/owner of the project.
    """
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
            role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN]
        ).exists()


class IsScanOwnerOrProjectMember(permissions.BasePermission):
    """
    Check if user owns the scan or is a project member.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        # Owner of scan
        if obj.initiated_by == request.user:
            return True

        # Project member
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project=obj.project,
            user=request.user
        ).exists()


class IsVulnerabilityAssigneeOrProjectMember(permissions.BasePermission):
    """
    Check if user is assigned to vulnerability or is project member.
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True

        # Assigned user
        if obj.assigned_to == request.user:
            return True

        # Project member
        from projects.models import ProjectMembership
        return ProjectMembership.objects.filter(
            project=obj.project,
            user=request.user
        ).exists()