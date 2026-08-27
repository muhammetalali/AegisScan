from django.db.models import F, Q
from django.http import FileResponse, HttpResponse
from django.utils.text import slugify
from projects.models import ProjectMembership
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Report, ReportTemplate
from .serializers import ReportSerializer


class ReportViewSet(viewsets.ModelViewSet):
    """مصدر التقارير الدائم، مع عزل كامل بحسب عضوية المشروع."""

    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "scan", "report_type", "format", "status"]
    search_fields = ["title", "description"]
    ordering_fields = ["created_at", "updated_at", "title", "status"]

    def get_queryset(self):
        queryset = Report.objects.select_related("project", "scan", "generated_by")
        user = self.request.user
        if user.is_superuser:
            return queryset
        return queryset.filter(
            Q(project__owner=user) | Q(project__members=user)
        ).distinct()

    def perform_create(self, serializer):
        if not self._can_manage_project(serializer.validated_data["project"]):
            raise PermissionDenied("Only project owners and administrators can create reports.")
        serializer.save(generated_by=self.request.user)

    def perform_update(self, serializer):
        if not self._can_manage_project(serializer.instance.project):
            raise PermissionDenied("Only project owners and administrators can update reports.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self._can_manage_project(instance.project):
            raise PermissionDenied("Only project owners and administrators can delete reports.")
        instance.delete()

    def _can_manage_project(self, project):
        user = self.request.user
        return (
            user.is_superuser
            or project.owner_id == user.id
            or project.memberships.filter(
                user=user,
                role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
            ).exists()
        )

    @action(detail=True, methods=["post"])
    def complete(self, request, pk=None):
        """اعتماد محتوى التقرير بعد إتمام المعالجة بواسطة العامل."""

        report = self.get_object()
        if not self._can_manage_project(report.project):
            raise PermissionDenied("Only project owners and administrators can complete reports.")
        serializer = self.get_serializer(
            report,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        report = serializer.save(status=Report.Status.COMPLETED)
        return Response(self.get_serializer(report).data)

    @action(detail=True, methods=["post"])
    def fail(self, request, pk=None):
        report = self.get_object()
        if not self._can_manage_project(report.project):
            raise PermissionDenied("Only project owners and administrators can fail reports.")
        report.status = Report.Status.FAILED
        report.error_message = request.data.get("error_message", "Report generation failed")
        report.save(update_fields=["status", "error_message", "updated_at"])
        return Response(self.get_serializer(report).data)

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        report = self.get_object()
        if report.status != Report.Status.COMPLETED:
            return Response(
                {"detail": "The report is not ready for download."},
                status=status.HTTP_409_CONFLICT,
            )

        Report.objects.filter(pk=report.pk).update(download_count=F("download_count") + 1)
        filename = f"{slugify(report.title) or 'aegisscan-report'}.{report.format}"
        if report.file:
            return FileResponse(
                report.file.open("rb"),
                as_attachment=True,
                filename=filename,
            )

        content_types = {
            Report.Format.JSON: "application/json",
            Report.Format.HTML: "text/html; charset=utf-8",
            Report.Format.MARKDOWN: "text/markdown; charset=utf-8",
            Report.Format.CSV: "text/csv; charset=utf-8",
        }
        response = HttpResponse(
            report.content,
            content_type=content_types.get(report.format, "application/octet-stream"),
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @action(detail=False, methods=["get"])
    def templates(self, request):
        templates = ReportTemplate.objects.filter(is_system=True).order_by(
            "report_type", "name"
        )
        return Response(
            [
                {
                    "id": template.id,
                    "name": template.name,
                    "description": template.description,
                    "report_type": template.report_type,
                    "format": template.format,
                    "variables": template.variables,
                    "is_default": template.is_default,
                }
                for template in templates
            ]
        )
