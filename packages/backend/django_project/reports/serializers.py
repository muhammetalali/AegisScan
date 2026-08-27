from projects.models import Project
from rest_framework import serializers
from scans.models import Scan

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    """واجهة آمنة للتقارير المملوكة للمشروع."""

    project_id = serializers.PrimaryKeyRelatedField(
        source="project",
        queryset=Project.objects.all(),
    )
    scan_id = serializers.PrimaryKeyRelatedField(
        source="scan",
        queryset=Scan.objects.all(),
        allow_null=True,
        required=False,
    )
    generated_by = serializers.PrimaryKeyRelatedField(read_only=True)
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = Report
        fields = [
            "id",
            "project_id",
            "scan_id",
            "title",
            "description",
            "report_type",
            "format",
            "status",
            "content",
            "file_size",
            "file_hash",
            "data_snapshot",
            "error_message",
            "generated_by",
            "generation_duration",
            "template_used",
            "is_public",
            "share_expires_at",
            "download_count",
            "download_url",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "file_size",
            "file_hash",
            "generated_by",
            "generation_duration",
            "error_message",
            "download_count",
            "download_url",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        request = self.context.get("request")
        project = attrs.get("project", getattr(self.instance, "project", None))
        scan = attrs.get("scan", getattr(self.instance, "scan", None))

        if request and project and not self._can_access_project(request.user, project):
            raise serializers.ValidationError(
                {"project_id": "You do not have access to this project."}
            )

        if scan and project and scan.project_id != project.id:
            raise serializers.ValidationError(
                {"scan_id": "The selected scan does not belong to the selected project."}
            )
        return attrs

    @staticmethod
    def _can_access_project(user, project):
        return (
            user.is_superuser
            or project.owner_id == user.id
            or project.members.filter(pk=user.pk).exists()
        )

    def get_download_url(self, obj):
        request = self.context.get("request")
        if not request:
            return None
        return request.build_absolute_uri(f"/api/v1/reports/{obj.pk}/download/")
