from django.utils import timezone
from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    project_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = Notification
        fields = [
            "id", "event_type", "title", "message", "priority", "status",
            "resource_type", "resource_id", "action_url", "project_id",
            "created_at", "sent_at", "read_at", "data",
        ]
        read_only_fields = fields


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """Durable in-app notifications backed by PostgreSQL."""

    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).select_related("project").order_by("-created_at")

    def list(self, request, *args, **kwargs):
        notifications = self.filter_queryset(self.get_queryset())[:100]
        unread_statuses = {Notification.Status.PENDING, Notification.Status.SENT, Notification.Status.DELIVERED}
        payload = self.get_serializer(notifications, many=True).data
        return Response({
            "items": payload,
            "count": len(payload),
            "unread_count": self.get_queryset().filter(status__in=unread_statuses).count(),
        })

    @action(detail=True, methods=["post"])
    def read(self, request, pk=None):
        notification = self.get_object()
        now = timezone.now()
        notification.status = Notification.Status.READ
        notification.read_at = notification.read_at or now
        notification.save(update_fields=["status", "read_at", "updated_at"])
        return Response(self.get_serializer(notification).data)

    @action(detail=False, methods=["post"])
    def read_all(self, request):
        now = timezone.now()
        updated = self.get_queryset().filter(
            status__in=[Notification.Status.PENDING, Notification.Status.SENT, Notification.Status.DELIVERED]
        ).update(status=Notification.Status.READ, read_at=now, updated_at=now)
        return Response({"updated": updated, "read_at": now.isoformat()})
