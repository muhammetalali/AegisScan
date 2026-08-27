from rest_framework import serializers

from .models import Scan, ScanEngine, ScanEngineExecution, ScanLog


class ScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = "__all__"
        read_only_fields = (
            "id", "status", "celery_task_id", "started_at", "completed_at",
            "duration", "progress", "current_phase", "current_engine",
            "security_score", "risk_level", "findings_count", "critical_count",
            "high_count", "medium_count", "low_count", "info_count",
            "false_positive_count", "engine_results", "error_message",
            "error_traceback", "initiated_by", "created_at", "updated_at",
        )


class ScanEngineSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanEngine
        fields = "__all__"


class ScanEngineExecutionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanEngineExecution
        fields = "__all__"


class ScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanLog
        fields = "__all__"
