from django.urls import re_path

from core.consumers import DashboardConsumer, NotificationConsumer, ScanProgressConsumer, SystemMonitorConsumer

websocket_urlpatterns = [
    re_path(r"ws/dashboard/$", DashboardConsumer.as_asgi()),
    re_path(r"ws/scan/(?P<scan_id>[^/]+)/$", ScanProgressConsumer.as_asgi()),
    re_path(r"ws/notifications/$", NotificationConsumer.as_asgi()),
    re_path(r"ws/system/monitor/$", SystemMonitorConsumer.as_asgi()),
]
