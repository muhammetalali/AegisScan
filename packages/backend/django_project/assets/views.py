from __future__ import annotations

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils.text import slugify
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from audit.models import AuditLog
from projects.models import Project

from .audit import (
    record_asset_audit,
    record_asset_relationship_audit,
    record_asset_technology_audit,
)
from .authorization import (
    user_can_create_asset,
    user_can_delete_asset,
    user_can_update_asset,
)
from .models import Asset, AssetRelationship, TechnologyFingerprint
from .serializers import AssetRelationshipSerializer, AssetSerializer, TechnologyFingerprintSerializer


class Conflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "The requested resource conflicts with existing state."
    default_code = "conflict"


class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "type", "environment", "criticality", "is_active"]
    search_fields = ["name", "slug", "description"]
    ordering_fields = ["created_at", "updated_at", "name", "criticality", "scan_count"]

    def get_queryset(self):
        qs = Asset.objects.select_related("project", "owner")
        user = self.request.user
        if not user.has_permission("asset.read"):
            return qs.none()
        if user.is_superuser:
            return qs
        return qs.filter(Q(project__owner=user) | Q(project__members=user)).distinct()

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not user_can_create_asset(project, self.request.user):
            raise PermissionDenied("You do not have permission to create assets in this project.")

        name = serializer.validated_data["name"]
        base = slugify(name) or "asset"
        slug = base
        suffix = 2
        while Asset.objects.filter(project=project, slug=slug).exists():
            slug = f"{base}-{suffix}"
            suffix += 1

        try:
            with transaction.atomic():
                asset = serializer.save(slug=slug, owner=self.request.user)
                record_asset_audit(
                    self.request,
                    action=AuditLog.Action.ASSET_CREATE,
                    asset=asset,
                    changes={"name": asset.name, "slug": asset.slug, "type": asset.type},
                )
        except IntegrityError as exc:
            raise Conflict("An asset with this slug already exists in the project.") from exc

    def perform_update(self, serializer):
        asset = serializer.instance
        if not user_can_update_asset(asset.project, self.request.user):
            raise PermissionDenied("You do not have permission to update assets in this project.")

        tracked = ("name", "slug", "type", "description", "environment", "criticality", "configuration", "tags", "metadata", "is_active")
        before = {field: getattr(asset, field) for field in tracked}
        with transaction.atomic():
            updated = serializer.save()
            changes = {
                field: {"from": before[field], "to": getattr(updated, field)}
                for field in tracked
                if before[field] != getattr(updated, field)
            }
            if changes:
                record_asset_audit(self.request, action=AuditLog.Action.ASSET_UPDATE, asset=updated, changes=changes)

    def perform_destroy(self, instance):
        if not user_can_delete_asset(instance.project, self.request.user):
            raise PermissionDenied("You do not have permission to delete assets in this project.")
        with transaction.atomic():
            record_asset_audit(
                self.request,
                action=AuditLog.Action.ASSET_DELETE,
                asset=instance,
                changes={"name": instance.name, "slug": instance.slug},
            )
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
        if not user.has_permission("asset.read"):
            return qs.none()
        if user.is_superuser:
            return qs
        return qs.filter(Q(project__owner=user) | Q(project__members=user)).distinct()

    @staticmethod
    def _validate_project_scope(source: Asset, target: Asset, project: Project) -> None:
        if source.project_id != target.project_id or project.pk != source.project_id:
            raise PermissionDenied("Asset relationships must stay within one project.")

    def perform_create(self, serializer):
        source = serializer.validated_data["source"]
        target = serializer.validated_data["target"]
        project = source.project
        self._validate_project_scope(source, target, project)
        if not user_can_create_asset(project, self.request.user):
            raise PermissionDenied("You do not have permission to create asset relationships in this project.")
        with transaction.atomic():
            relationship = serializer.save(project=project)
            record_asset_relationship_audit(
                self.request,
                action=AuditLog.Action.ASSET_RELATIONSHIP_CREATE,
                relationship=relationship,
                changes={"relationship_type": relationship.relationship_type},
            )

    def perform_update(self, serializer):
        relationship = serializer.instance
        if not user_can_update_asset(relationship.project, self.request.user):
            raise PermissionDenied("You do not have permission to update asset relationships in this project.")
        source = serializer.validated_data.get("source", relationship.source)
        target = serializer.validated_data.get("target", relationship.target)
        self._validate_project_scope(source, target, relationship.project)
        before = {
            "source": str(relationship.source_id),
            "target": str(relationship.target_id),
            "relationship_type": relationship.relationship_type,
            "metadata": relationship.metadata,
        }
        with transaction.atomic():
            updated = serializer.save(project=relationship.project)
            after = {
                "source": str(updated.source_id),
                "target": str(updated.target_id),
                "relationship_type": updated.relationship_type,
                "metadata": updated.metadata,
            }
            changes = {
                key: {"from": before[key], "to": after[key]}
                for key in before
                if before[key] != after[key]
            }
            if changes:
                record_asset_relationship_audit(
                    self.request,
                    action=AuditLog.Action.ASSET_RELATIONSHIP_UPDATE,
                    relationship=updated,
                    changes=changes,
                )

    def perform_destroy(self, instance):
        if not user_can_delete_asset(instance.project, self.request.user):
            raise PermissionDenied("You do not have permission to delete asset relationships in this project.")
        with transaction.atomic():
            record_asset_relationship_audit(
                self.request,
                action=AuditLog.Action.ASSET_RELATIONSHIP_DELETE,
                relationship=instance,
                changes={"relationship_type": instance.relationship_type},
            )
            instance.delete()


class TechnologyFingerprintViewSet(viewsets.ModelViewSet):
    serializer_class = TechnologyFingerprintSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = TechnologyFingerprint.objects.select_related("asset", "asset__project")
        user = self.request.user
        if not user.has_permission("asset.read"):
            return qs.none()
        if user.is_superuser:
            return qs
        return qs.filter(Q(asset__project__owner=user) | Q(asset__project__members=user)).distinct()

    def perform_create(self, serializer):
        asset = serializer.validated_data["asset"]
        if not user_can_create_asset(asset.project, self.request.user):
            raise PermissionDenied("You do not have permission to create technology fingerprints in this project.")
        with transaction.atomic():
            technology = serializer.save()
            record_asset_technology_audit(
                self.request,
                action=AuditLog.Action.ASSET_TECHNOLOGY_CREATE,
                technology=technology,
                changes={"name": technology.name, "version": technology.version, "category": technology.category},
            )

    def perform_update(self, serializer):
        technology = serializer.instance
        current_project = technology.asset.project
        if not user_can_update_asset(current_project, self.request.user):
            raise PermissionDenied("You do not have permission to update technology fingerprints in this project.")
        target_asset = serializer.validated_data.get("asset", technology.asset)
        if target_asset.project_id != current_project.pk:
            raise PermissionDenied("Technology fingerprints cannot move between projects.")
        tracked = ("asset_id", "name", "version", "category", "confidence", "source", "evidence")
        before = {field: getattr(technology, field) for field in tracked}
        with transaction.atomic():
            updated = serializer.save()
            changes = {
                field: {
                    "from": str(before[field]) if field == "asset_id" else before[field],
                    "to": str(getattr(updated, field)) if field == "asset_id" else getattr(updated, field),
                }
                for field in tracked
                if before[field] != getattr(updated, field)
            }
            if changes:
                record_asset_technology_audit(
                    self.request,
                    action=AuditLog.Action.ASSET_TECHNOLOGY_UPDATE,
                    technology=updated,
                    changes=changes,
                )

    def perform_destroy(self, instance):
        if not user_can_delete_asset(instance.asset.project, self.request.user):
            raise PermissionDenied("You do not have permission to delete technology fingerprints in this project.")
        with transaction.atomic():
            record_asset_technology_audit(
                self.request,
                action=AuditLog.Action.ASSET_TECHNOLOGY_DELETE,
                technology=instance,
                changes={"name": instance.name, "asset_id": str(instance.asset_id)},
            )
            instance.delete()
