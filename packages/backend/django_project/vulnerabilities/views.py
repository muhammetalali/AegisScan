from django.db.models import Q
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from projects.models import ProjectMembership
from .models import Vulnerability, VulnerabilityEvidence, VulnerabilityNote, VulnerabilityStatusHistory
from .serializers import VulnerabilityEvidenceSerializer, VulnerabilityNoteSerializer, VulnerabilitySerializer


class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "scan", "asset", "severity", "status", "confidence", "assigned_to"]
    search_fields = ["title", "description", "cwe_id", "owasp_category", "file_path"]
    ordering_fields = ["created_at", "updated_at", "risk_score", "cvss_score", "severity"]

    def get_queryset(self):
        qs = Vulnerability.objects.select_related("project", "scan", "asset", "assigned_to")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(project__owner=user) | Q(project__members=user)).distinct()

    def _can_manage(self, project):
        user = self.request.user
        return user.is_superuser or project.owner_id == user.id or project.memberships.filter(
            user=user, role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN]
        ).exists()

    def perform_update(self, serializer):
        instance = serializer.instance
        if not self._can_manage(instance.project):
            raise PermissionDenied("Only project owners and administrators can update vulnerabilities.")
        old_status = instance.status
        updated = serializer.save()
        if old_status != updated.status:
            VulnerabilityStatusHistory.objects.create(
                vulnerability=updated, old_status=old_status, new_status=updated.status,
                changed_by=self.request.user,
            )

    @action(detail=True, methods=["get"])
    def evidences(self, request, pk=None):
        return Response(VulnerabilityEvidenceSerializer(self.get_object().evidences.all(), many=True).data)

    @action(detail=True, methods=["post"])
    def notes(self, request, pk=None):
        vulnerability = self.get_object()
        serializer = VulnerabilityNoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        note = serializer.save(vulnerability=vulnerability, author=request.user)
        return Response(VulnerabilityNoteSerializer(note).data, status=201)

    @action(detail=True, methods=["post"])
    def verify(self, request, pk=None):
        vulnerability = self.get_object()
        if not self._can_manage(vulnerability.project):
            raise PermissionDenied("Only project owners and administrators can verify vulnerabilities.")
        vulnerability.validation_status = "verified"
        vulnerability.validated_at = timezone.now()
        vulnerability.validated_by = request.user
        vulnerability.save(update_fields=["validation_status", "validated_at", "validated_by", "updated_at"])
        return Response(self.get_serializer(vulnerability).data)


class VulnerabilityEvidenceViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilityEvidenceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = VulnerabilityEvidence.objects.select_related("vulnerability", "vulnerability__project")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(vulnerability__project__owner=user) | Q(vulnerability__project__members=user)).distinct()

    def perform_create(self, serializer):
        serializer.save()


class VulnerabilityNoteViewSet(viewsets.ModelViewSet):
    serializer_class = VulnerabilityNoteSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = VulnerabilityNote.objects.select_related("vulnerability", "vulnerability__project", "author")
        user = self.request.user
        if user.is_superuser:
            return qs
        return qs.filter(Q(vulnerability__project__owner=user) | Q(vulnerability__project__members=user)).distinct()

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
