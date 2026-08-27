from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = (
            "id", "user", "action", "result", "resource_type", "resource_id",
            "resource_repr", "changes", "metadata", "ip_address", "user_agent",
            "location", "session_id", "request_id", "error_message", "duration_ms",
            "created_at",
        )
        read_only_fields = fields
