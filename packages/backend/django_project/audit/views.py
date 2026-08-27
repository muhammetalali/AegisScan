from rest_framework import viewsets
from rest_framework.permissions import IsAdminUser

from .models import AuditLog
from .serializers import AuditLogSerializer


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Django is the authoritative owner of durable audit history."""

    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]
    filterset_fields = ["user", "action", "result", "resource_type", "resource_id"]
    search_fields = ["resource_type", "resource_id", "resource_repr", "error_message"]
    ordering_fields = ["created_at", "action", "result", "duration_ms"]

    def get_queryset(self):
        return AuditLog.objects.select_related("user").all()
