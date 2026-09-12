from django.urls import re_path

from django_project.core.consumers import (
    NotificationConsumer,
    ScanProgressConsumer,
    SystemMonitorConsumer,
)

websocket_urlpatterns = [
    re_path(r"ws/scan/(?P<scan_id>[^/]+)/$", ScanProgressConsumer.as_asgi()),
    re_path(r"ws/notifications/$", NotificationConsumer.as_asgi()),
    re_path(r"ws/system/monitor/$", SystemMonitorConsumer.as_asgi()),
]
