from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import Notification


class NotificationViewSet(viewsets.ReadOnlyModelViewSet):
    """Durable in-app notifications backed by PostgreSQL."""

    permission_classes = [IsAuthenticated]
    serializer_class = None

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).select_related("project").order_by("-created_at")

    def list(self, request, *args, **kwargs):
        notifications = self.filter_queryset(self.get_queryset())[:100]
        unread_statuses = {
            Notification.Status.PENDING,
            Notification.Status.SENT,
            Notification.Status.DELIVERED,
        }
        payload = [self._serialize(item) for item in notifications]
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
        return Response(self._serialize(notification))

    @action(detail=False, methods=["post"])
    def read_all(self, request):
        now = timezone.now()
        updated = self.get_queryset().filter(
            status__in=[
                Notification.Status.PENDING,
                Notification.Status.SENT,
                Notification.Status.DELIVERED,
            ]
        ).update(status=Notification.Status.READ, read_at=now, updated_at=now)
        return Response({"updated": updated, "read_at": now.isoformat()})

    @staticmethod
    def _serialize(notification):
        return {
            "id": str(notification.id),
            "event_type": notification.event_type,
            "title": notification.title,
            "message": notification.message,
            "priority": notification.priority,
            "status": notification.status,
            "resource_type": notification.resource_type,
            "resource_id": notification.resource_id,
            "action_url": notification.action_url or None,
            "project_id": str(notification.project_id) if notification.project_id else None,
            "created_at": notification.created_at.isoformat(),
            "sent_at": notification.sent_at.isoformat() if notification.sent_at else None,
            "read_at": notification.read_at.isoformat() if notification.read_at else None,
            "data": notification.data,
        }
