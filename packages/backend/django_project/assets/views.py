from django.db.models import Q
from django.utils.text import slugify
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from projects.models import ProjectMembership
from .models import Asset, AssetRelationship, TechnologyFingerprint
from .serializers import AssetRelationshipSerializer, AssetSerializer, TechnologyFingerprintSerializer


class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "type", "environment", "criticality", "is_active"]
    search_fields = ["name", "slug", "description"]
    ordering_fields = ["created_at", "updated_at", "name", "criticality", "scan_count"]

    def get_queryset(self):
        qs = Asset.objects.select_related("project", "owner")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(project__owner=user) | Q(project__members=user)).distinct()

    def _can_manage(self, project):
        user = self.request.user
        return user.is_superuser or project.owner_id == user.id or project.memberships.filter(
            user=user, role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN]
        ).exists()

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not self._can_manage(project):
            raise PermissionDenied("Only project owners and administrators can create assets.")
        name = serializer.validated_data["name"]
        base = slugify(name) or "asset"
        slug = base
        suffix = 2
        while Asset.objects.filter(project=project, slug=slug).exists():
            slug = f"{base}-{suffix}"
            suffix += 1
        serializer.save(slug=slug, owner=self.request.user)

    def perform_update(self, serializer):
        if not self._can_manage(serializer.instance.project):
            raise PermissionDenied("Only project owners and administrators can update assets.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self._can_manage(instance.project):
            raise PermissionDenied("Only project owners and administrators can delete assets.")
        instance.delete()

    @action(detail=True, methods=["get"])
    def technologies(self, request, pk=None):
        asset = self.get_object()
        return Response(TechnologyFingerprintSerializer(asset.technologies.all(), many=True).data)

    @action(detail=True, methods=["get"])
    def relationships(self, request, pk=None):
        asset = self.get_object()
        qs = AssetRelationship.objects.filter(source=asset).select_related("target")
        return Response(AssetRelationshipSerializer(qs, many=True).data)


class AssetRelationshipViewSet(viewsets.ModelViewSet):
    serializer_class = AssetRelationshipSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = AssetRelationship.objects.select_related("project", "source", "target")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(project__owner=user) | Q(project__members=user)).distinct()

    def perform_create(self, serializer):
        source = serializer.validated_data["source"]
        target = serializer.validated_data["target"]
        if source.project_id != target.project_id:
            raise PermissionDenied("Asset relationships must stay within one project.")
        serializer.save(project=source.project)


class TechnologyFingerprintViewSet(viewsets.ModelViewSet):
    serializer_class = TechnologyFingerprintSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = TechnologyFingerprint.objects.select_related("asset", "asset__project")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(asset__project__owner=user) | Q(asset__project__members=user)).distinct()
