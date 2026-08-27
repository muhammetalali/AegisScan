from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from projects.models import Project

from .models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceReport,
)
from .serializers import (
    ComplianceAssessmentSerializer,
    ComplianceAssessmentWriteSerializer,
    ComplianceControlSerializer,
    ComplianceFrameworkSerializer,
    ComplianceReportSerializer,
)


def accessible_projects(user):
    if user.is_superuser:
        return Project.objects.all()
    return Project.objects.filter(Q(owner=user) | Q(members=user)).distinct()


def can_manage_project(user, project):
    return (
        user.is_superuser
        or project.owner_id == user.id
        or project.memberships.filter(user=user, role__in=["owner", "admin"]).exists()
    )


class ComplianceFrameworkViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ComplianceFramework.objects.filter(is_active=True)
    serializer_class = ComplianceFrameworkSerializer
    permission_classes = [IsAuthenticated]
    search_fields = ["name", "framework_type", "version"]

    @action(detail=True, methods=["get"])
    def controls(self, request, pk=None):
        framework = self.get_object()
        queryset = ComplianceControl.objects.filter(framework=framework)
        return Response(ComplianceControlSerializer(queryset, many=True).data)


class ComplianceControlViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ComplianceControl.objects.select_related("framework").filter(
        framework__is_active=True
    )
    serializer_class = ComplianceControlSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["framework", "priority", "category"]
    search_fields = ["control_id", "title", "description"]


class ComplianceAssessmentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "framework", "control", "status"]
    search_fields = ["evidence", "notes", "remediation_plan"]

    def get_queryset(self):
        return ComplianceAssessment.objects.select_related(
            "project", "framework", "control", "assessed_by"
        ).filter(project__in=accessible_projects(self.request.user))

    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return ComplianceAssessmentWriteSerializer
        return ComplianceAssessmentSerializer

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        if not project or not can_manage_project(self.request.user, project):
            raise PermissionDenied("Only project owners and administrators can assess compliance.")
        serializer.save(
            project=project,
            assessed_by=self.request.user,
            assessed_at=timezone.now(),
        )

    def perform_update(self, serializer):
        if not can_manage_project(self.request.user, serializer.instance.project):
            raise PermissionDenied("Only project owners and administrators can update assessments.")
        serializer.save(assessed_by=self.request.user, assessed_at=timezone.now())

    def perform_destroy(self, instance):
        if not can_manage_project(self.request.user, instance.project):
            raise PermissionDenied("Only project owners and administrators can delete assessments.")
        instance.delete()


class ComplianceReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ComplianceReportSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ["project", "framework", "overall_status"]

    def get_queryset(self):
        return ComplianceReport.objects.select_related(
            "project", "framework", "generated_by"
        ).filter(project__in=accessible_projects(self.request.user))

    @action(detail=False, methods=["post"])
    def generate(self, request):
        project = Project.objects.filter(pk=request.data.get("project_id")).first()
        framework = ComplianceFramework.objects.filter(
            pk=request.data.get("framework_id"), is_active=True
        ).first()
        if not project or not framework:
            return Response(
                {"detail": "A valid project_id and framework_id are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not can_manage_project(request.user, project):
            raise PermissionDenied("Only project owners and administrators can generate reports.")

        controls = list(ComplianceControl.objects.filter(framework=framework))
        assessments = {
            item.control_id: item
            for item in ComplianceAssessment.objects.filter(
                project=project, framework=framework
            )
        }
        counts = {
            "compliant": 0,
            "non_compliant": 0,
            "partial": 0,
            "not_applicable": 0,
            "not_assessed": 0,
        }
        details = []
        for control in controls:
            assessment = assessments.get(control.id)
            current_status = assessment.status if assessment else "not_assessed"
            counts[current_status] = counts.get(current_status, 0) + 1
            details.append(
                {
                    "control_id": control.control_id,
                    "title": control.title,
                    "status": current_status,
                    "assessment_id": str(assessment.id) if assessment else None,
                }
            )

        applicable = counts["compliant"] + counts["non_compliant"] + counts["partial"]
        percentage = round(
            ((counts["compliant"] + counts["partial"] * 0.5) / applicable) * 100,
            2,
        ) if applicable else 0.0
        if counts["non_compliant"]:
            overall_status = "non_compliant"
        elif counts["partial"] or counts["not_assessed"]:
            overall_status = "partial"
        elif counts["compliant"] or counts["not_applicable"]:
            overall_status = "compliant"
        else:
            overall_status = "not_assessed"

        report = ComplianceReport.objects.create(
            project=project,
            framework=framework,
            title=f"{framework.name} compliance report — {project.name}",
            overall_status=overall_status,
            total_controls=len(controls),
            compliant_count=counts["compliant"],
            non_compliant_count=counts["non_compliant"],
            partial_count=counts["partial"],
            not_applicable_count=counts["not_applicable"],
            compliance_percentage=percentage,
            report_data={"controls": details, "counts": counts},
            generated_by=request.user,
        )
        return Response(self.get_serializer(report).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"])
    def dashboard(self, request):
        project = Project.objects.filter(pk=request.query_params.get("project_id")).first()
        if not project or not accessible_projects(request.user).filter(pk=project.pk).exists():
            return Response({"detail": "Project not found."}, status=status.HTTP_404_NOT_FOUND)
        queryset = ComplianceAssessment.objects.filter(project=project)
        counts = dict(
            queryset.values("status").annotate(total=Count("id")).values_list("status", "total")
        )
        total = sum(counts.values())
        compliant = counts.get("compliant", 0)
        partial = counts.get("partial", 0)
        return Response(
            {
                "project_id": str(project.id),
                "total_assessments": total,
                "counts": counts,
                "compliance_percentage": round(
                    ((compliant + partial * 0.5) / total) * 100, 2
                ) if total else 0.0,
            }
        )
