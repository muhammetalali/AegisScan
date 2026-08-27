from rest_framework import serializers
from projects.models import Project

from .models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceReport,
)


class ComplianceFrameworkSerializer(serializers.ModelSerializer):
    controls_count = serializers.SerializerMethodField()

    class Meta:
        model = ComplianceFramework
        fields = [
            "id",
            "name",
            "framework_type",
            "version",
            "description",
            "is_active",
            "is_system",
            "controls_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "controls_count", "created_at", "updated_at"]

    def get_controls_count(self, obj):
        return obj.controls.count()


class ComplianceControlSerializer(serializers.ModelSerializer):
    framework_id = serializers.PrimaryKeyRelatedField(
        source="framework", queryset=ComplianceFramework.objects.all()
    )

    class Meta:
        model = ComplianceControl
        fields = [
            "id",
            "framework_id",
            "control_id",
            "title",
            "description",
            "priority",
            "category",
            "related_controls",
            "references",
            "implementation_guidance",
            "testing_procedure",
            "remediation_deadline_days",
            "metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class ComplianceAssessmentSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(source="project", read_only=True)
    framework_id = serializers.PrimaryKeyRelatedField(source="framework", read_only=True)
    control_id = serializers.PrimaryKeyRelatedField(source="control", read_only=True)
    assessed_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = ComplianceAssessment
        fields = [
            "id",
            "project_id",
            "scan",
            "framework_id",
            "control_id",
            "status",
            "evidence",
            "findings",
            "remediation_plan",
            "remediation_deadline",
            "assessed_by",
            "assessed_at",
            "next_review",
            "notes",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "project_id",
            "framework_id",
            "control_id",
            "assessed_by",
            "assessed_at",
            "created_at",
            "updated_at",
        ]


class ComplianceAssessmentWriteSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(
        source="project", queryset=Project.objects.all()
    )
    framework_id = serializers.PrimaryKeyRelatedField(
        source="framework", queryset=ComplianceFramework.objects.all()
    )
    control_id = serializers.PrimaryKeyRelatedField(
        source="control", queryset=ComplianceControl.objects.all()
    )

    class Meta:
        model = ComplianceAssessment
        fields = [
            "project_id",
            "scan",
            "framework_id",
            "control_id",
            "status",
            "evidence",
            "findings",
            "remediation_plan",
            "remediation_deadline",
            "next_review",
            "notes",
        ]

    def validate(self, attrs):
        framework = attrs["framework"]
        control = attrs["control"]
        if control.framework_id != framework.id:
            raise serializers.ValidationError(
                {"control_id": "The control must belong to the selected framework."}
            )
        scan = attrs.get("scan")
        project = attrs["project"]
        if scan and scan.project_id != project.id:
            raise serializers.ValidationError(
                {"scan": "The selected scan must belong to the selected project."}
            )
        return attrs


class ComplianceReportSerializer(serializers.ModelSerializer):
    project_id = serializers.PrimaryKeyRelatedField(source="project", read_only=True)
    framework_id = serializers.PrimaryKeyRelatedField(source="framework", read_only=True)
    generated_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = ComplianceReport
        fields = [
            "id",
            "project_id",
            "framework_id",
            "title",
            "overall_status",
            "total_controls",
            "compliant_count",
            "non_compliant_count",
            "partial_count",
            "not_applicable_count",
            "compliance_percentage",
            "report_data",
            "generated_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
