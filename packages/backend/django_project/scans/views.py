from django.db.models import Q
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from projects.models import ProjectMembership
from .models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from .serializers import ScanSerializer, ScanEngineSerializer, ScanEngineExecutionSerializer, ScanLogSerializer


def visible_projects(user):
    if user.is_superuser:
        return None
    # Scan does not have an owner/members relation of its own. Tenant scope
    # must be applied through the owning Project relationship.
    return Q(project__owner=user) | Q(project__members=user)


class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "asset", "scan_type", "status", "depth"]
    search_fields = ["name", "current_phase", "current_engine"]
    ordering_fields = ["created_at", "updated_at", "progress", "security_score"]

    def get_queryset(self):
        qs = Scan.objects.select_related("project", "asset", "initiated_by")
        scope = visible_projects(self.request.user)
        return qs if scope is None else qs.filter(scope).distinct()

    def _can_manage(self, project):
        user = self.request.user
        return user.is_superuser or project.owner_id == user.id or project.memberships.filter(
            user=user, role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN]
        ).exists()

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not self._can_manage(project):
            raise PermissionDenied("Only project owners and administrators can create scans.")
        serializer.save(initiated_by=self.request.user)

    def perform_update(self, serializer):
        if not self._can_manage(serializer.instance.project):
            raise PermissionDenied("Only project owners and administrators can update scans.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self._can_manage(instance.project):
            raise PermissionDenied("Only project owners and administrators can delete scans.")
        instance.delete()

    @action(detail=True, methods=["get"])
    def logs(self, request, pk=None):
        scan = self.get_object()
        limit = min(int(request.query_params.get("limit", 100)), 500)
        return Response(ScanLogSerializer(scan.logs.all()[:limit], many=True).data)

    @action(detail=True, methods=["get"], url_path="engine-executions")
    def engine_executions(self, request, pk=None):
        scan = self.get_object()
        return Response(ScanEngineExecutionSerializer(scan.engine_executions.all(), many=True).data)


class ScanEngineViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ScanEngine.objects.all()
    serializer_class = ScanEngineSerializer
    permission_classes = [IsAuthenticated]


class ScanEngineExecutionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ScanEngineExecutionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = ScanEngineExecution.objects.select_related("scan", "engine", "scan__project")
        scope = visible_projects(self.request.user)
        return qs if scope is None else qs.filter(scope).distinct()
