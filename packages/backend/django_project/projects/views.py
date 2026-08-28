from __future__ import annotations

from django.db import transaction
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from audit.models import AuditLog
from audit.services import append_audit
from users.models import User

from .authorization import get_project_authorization
from .models import Project, ProjectMembership
from .serializers import ProjectSerializer


def _request_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (forwarded.split(",", 1)[0].strip() if forwarded else request.META.get("REMOTE_ADDR")) or "0.0.0.0"


def _audit(request, *, action: str, project: Project, changes=None, result=AuditLog.Result.SUCCESS, error_message=""):
    return append_audit(
        action=action,
        ip_address=_request_ip(request),
        user=request.user,
        result=result,
        resource_type="Project",
        resource_id=str(project.pk),
        resource_repr=project.name,
        changes=changes or {},
        metadata={"environment": project.environment, "status": project.status},
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        session_id=request.session.session_key or "",
        error_message=error_message[:500],
        request_id=getattr(request, "request_id", None),
    )


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [IsAuthenticated]
    search_fields = ["name", "slug", "description"]
    ordering_fields = ["created_at", "updated_at", "name", "status", "environment"]
    filterset_fields = ["status", "environment", "owner"]

    def get_queryset(self):
        qs = Project.objects.select_related("owner").prefetch_related("memberships__user")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(models.Q(owner=user) | models.Q(members=user)).distinct()

    def _authorization(self, project):
        authz = get_project_authorization(project.pk, self.request.user)
        if project.owner_id == self.request.user.id:
            return authz.__class__(
                ProjectMembership(project=project, user=self.request.user, role=ProjectMembership.Role.OWNER)
            )
        return authz

    def perform_create(self, serializer):
        with transaction.atomic():
            project = serializer.save(owner=self.request.user)
            ProjectMembership.objects.create(
                project=project,
                user=self.request.user,
                role=ProjectMembership.Role.OWNER,
            )
            _audit(self.request, action=AuditLog.Action.PROJECT_CREATE, project=project, changes={"name": project.name, "slug": project.slug})

    def perform_update(self, serializer):
        project = serializer.instance
        authz = self._authorization(project)
        if not authz.can_update:
            raise PermissionDenied("Only project owners and administrators can update projects.")
        before = {field: getattr(project, field) for field in ("name", "slug", "description", "status", "environment", "tags", "settings", "default_scan_config")}
        updated = serializer.save()
        changes = {field: {"from": before[field], "to": getattr(updated, field)} for field in before if before[field] != getattr(updated, field)}
        _audit(self.request, action=AuditLog.Action.PROJECT_UPDATE, project=updated, changes=changes)

    def perform_destroy(self, instance):
        authz = self._authorization(instance)
        if not authz.can_delete:
            raise PermissionDenied("Only the project owner can delete a project.")
        _audit(self.request, action=AuditLog.Action.PROJECT_DELETE, project=instance)
        instance.delete()

    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        project = self.get_object()
        authz = self._authorization(project)
        if not authz.can_archive:
            raise PermissionDenied("Only project owners and administrators can archive projects.")
        if project.status == Project.Status.ARCHIVED:
            return Response(ProjectSerializer(project).data)
        project.status = Project.Status.ARCHIVED
        project.archived_at = timezone.now()
        project.save(update_fields=["status", "archived_at", "updated_at"])
        _audit(request, action=AuditLog.Action.PROJECT_ARCHIVE, project=project, changes={"status": Project.Status.ARCHIVED})
        return Response(ProjectSerializer(project).data)

    @action(detail=True, methods=["post"])
    def members(self, request, pk=None):
        project = self.get_object()
        authz = self._authorization(project)
        if not authz.can_manage_members:
            raise PermissionDenied("Only project owners and administrators can manage members.")
        email = str(request.data.get("email", "")).strip().lower()
        role = str(request.data.get("role", ProjectMembership.Role.MEMBER)).strip().lower()
        if not email:
            return Response({"detail": "email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            target_user = User.objects.get(email__iexact=email)
        except User.DoesNotExist as exc:
            raise NotFound("User not found.") from exc
        if not authz.can_change_role_to(role):
            raise PermissionDenied("You cannot grant that role.")
        membership, created = ProjectMembership.objects.get_or_create(
            project=project,
            user=target_user,
            defaults={"role": role},
        )
        if not created:
            raise Response({"detail": "User is already a project member."}, status=status.HTTP_409_CONFLICT)
        _audit(request, action=AuditLog.Action.PROJECT_MEMBER_ADD, project=project, changes={"user_id": str(target_user.pk), "role": role})
        return Response({"id": str(membership.pk), "user_id": str(target_user.pk), "role": membership.role}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["patch", "delete"], url_path=r"members/(?P<user_id>[^/.]+)")
    def member_detail(self, request, pk=None, user_id=None):
        project = self.get_object()
        authz = self._authorization(project)
        if not authz.can_manage_members:
            raise PermissionDenied("Only project owners and administrators can manage members.")
        try:
            membership = project.memberships.select_related("user").get(user_id=user_id)
        except ProjectMembership.DoesNotExist as exc:
            raise NotFound("Project membership not found.") from exc

        if request.method == "DELETE":
            if not authz.can_manage_membership(membership):
                raise PermissionDenied("You cannot remove this member.")
            if membership.user_id == request.user.id and membership.role == ProjectMembership.Role.OWNER:
                raise PermissionDenied("The project owner cannot remove their own membership.")
            _audit(request, action=AuditLog.Action.PROJECT_MEMBER_REMOVE, project=project, changes={"user_id": str(membership.user_id), "role": membership.role})
            membership.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        new_role = str(request.data.get("role", "")).strip().lower()
        if not authz.can_manage_membership(membership, new_role=new_role) or not authz.can_change_role_to(new_role):
            raise PermissionDenied("You cannot assign that role.")
        old_role = membership.role
        membership.role = new_role
        membership.save(update_fields=["role"])
        _audit(request, action=AuditLog.Action.PROJECT_MEMBER_ROLE_CHANGE, project=project, changes={"user_id": str(membership.user_id), "from": old_role, "to": new_role})
        return Response({"id": str(membership.pk), "user_id": str(membership.user_id), "role": membership.role})
