import asyncio
import json

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model

User = get_user_model()


class BaseConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope.get("user")
        if not self.user or self.user.is_anonymous:
            await self.close(code=4001)
            return
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def send_json(self, data):
        await self.send(text_data=json.dumps(data))


class ScanProgressConsumer(BaseConsumer):
    async def connect(self):
        await super().connect()
        self.scan_id = self.scope["url_route"]["kwargs"]["scan_id"]
        self.room_group_name = f"scan_{self.scan_id}"

        has_access = await self.check_scan_access()
        if not has_access:
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

    async def disconnect(self, close_code):
        if hasattr(self, "room_group_name"):
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    @database_sync_to_async
    def check_scan_access(self):
        from scans.models import Scan

        try:
            scan = Scan.objects.get(id=self.scan_id)
            return scan.project.owner == self.user or self.user in scan.project.members.all() or self.user.is_staff
        except Scan.DoesNotExist:
            return False

    async def scan_progress(self, event):
        await self.send_json({
            "type": "scan_progress",
            "scan_id": self.scan_id,
            "phase": event["phase"],
            "progress": event["progress"],
            "message": event.get("message", ""),
            "engines": event.get("engines", []),
        })

    async def scan_completed(self, event):
        await self.send_json({
            "type": "scan_completed",
            "scan_id": self.scan_id,
            "status": event["status"],
            "result": event.get("result", {}),
        })

    async def scan_error(self, event):
        await self.send_json({
            "type": "scan_error",
            "scan_id": self.scan_id,
            "error": event["error"],
        })


class DashboardConsumer(BaseConsumer):
    """Authenticated live dashboard stream with tenant-scoped snapshots."""

    async def connect(self):
        await super().connect()
        self.poll_task = asyncio.create_task(self._stream_snapshots())

    async def disconnect(self, close_code):
        task = getattr(self, "poll_task", None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _stream_snapshots(self):
        previous = None
        try:
            while True:
                snapshot = await self.get_snapshot()
                if snapshot != previous:
                    await self.send_json({"type": "dashboard_snapshot", "data": snapshot})
                    previous = snapshot
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            raise

    @database_sync_to_async
    def get_snapshot(self):
        from core.dashboard import build_dashboard_snapshot

        return build_dashboard_snapshot(self.user)


class NotificationConsumer(BaseConsumer):
    async def connect(self):
        await super().connect()
        self.user_group_name = f"user_{self.user.id}"
        await self.channel_layer.group_add(self.user_group_name, self.channel_name)

    async def disconnect(self, close_code):
        if hasattr(self, "user_group_name"):
            await self.channel_layer.group_discard(self.user_group_name, self.channel_name)

    async def notification(self, event):
        await self.send_json({
            "type": "notification",
            "id": event["id"],
            "title": event["title"],
            "message": event["message"],
            "level": event.get("level", "info"),
            "action_url": event.get("action_url"),
            "created_at": event["created_at"],
        })


class SystemMonitorConsumer(BaseConsumer):
    async def connect(self):
        await super().connect()
        if not self.user.is_staff:
            await self.close(code=4003)
            return
        self.room_group_name = "system_monitor"
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)

    async def disconnect(self, close_code):
        if hasattr(self, "room_group_name"):
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def system_metrics(self, event):
        await self.send_json({
            "type": "system_metrics",
            "cpu_percent": event["cpu_percent"],
            "memory_percent": event["memory_percent"],
            "disk_percent": event["disk_percent"],
            "active_scans": event["active_scans"],
            "queue_length": event["queue_length"],
            "timestamp": event["timestamp"],
        })

    async def celery_status(self, event):
        await self.send_json({
            "type": "celery_status",
            "workers": event["workers"],
            "active_tasks": event["active_tasks"],
            "scheduled_tasks": event["scheduled_tasks"],
        })
