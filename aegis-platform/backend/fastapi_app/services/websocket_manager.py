from typing import Dict, List, Set
from fastapi import WebSocket
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

class WebSocketManager:
    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.user_connections: Dict[str, Set[WebSocket]] = {}
        self.connection_identity: dict[WebSocket, tuple[str, int]] = {}

    async def connect(self, channel: str, websocket: WebSocket, identity: dict | None = None):
        if websocket not in self.connection_identity:
            if not identity or type(identity.get('auth_version')) is not int:
                raise ValueError('Authenticated WebSocket identity required')
            await websocket.accept()
            self.connection_identity[websocket] = (
                str(identity.get('user_id') or ''), identity['auth_version'],
            )
        self.connections.setdefault(channel, set()).add(websocket)
        logger.info(f"WebSocket connected to {channel}. Total connections: {len(self.connections[channel])}")

    def disconnect(self, channel: str, websocket: WebSocket):
        if channel in self.connections:
            self.connections[channel].discard(websocket)
            if not self.connections[channel]:
                del self.connections[channel]
        if not any(websocket in sockets for sockets in self.connections.values()):
            self.connection_identity.pop(websocket, None)
        logger.info(f"WebSocket disconnected from {channel}")

    async def _authorized_for_send(self, websocket: WebSocket) -> bool:
        # Revalidate before EACH broadcast; periodic WS receive checks bound the
        # lifetime of an idle revoked connection separately.
        from ..core.dependencies import _is_active_user
        identity = self.connection_identity.get(websocket)
        if identity and await _is_active_user(*identity):
            return True
        try:
            await websocket.close(code=4001)
        except Exception:
            pass
        for channel in list(self.connections):
            self.disconnect(channel, websocket)
        return False

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        if not await self._authorized_for_send(websocket):
            return
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast(self, channel: str, message: dict):
        if channel not in self.connections:
            return
        disconnected = set()
        for websocket in list(self.connections[channel]):
            if not await self._authorized_for_send(websocket):
                continue
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {channel}: {e}")
                disconnected.add(websocket)
        for ws in disconnected:
            self.disconnect(channel, ws)

    async def broadcast_to_user(self, user_id: str, message: dict):
        channel = f"user_{user_id}"
        await self.broadcast(channel, message)

    async def broadcast_scan_progress(self, scan_id: str, progress_data: dict):
        await self.broadcast(f"scan_{scan_id}", {
            "type": "scan_progress",
            "scan_id": scan_id,
            **progress_data
        })

    async def broadcast_scan_completed(self, scan_id: str, result: dict):
        await self.broadcast(f"scan_{scan_id}", {
            "type": "scan_completed",
            "scan_id": scan_id,
            "result": result
        })

    async def broadcast_scan_error(self, scan_id: str, error: str):
        await self.broadcast(f"scan_{scan_id}", {
            "type": "scan_error",
            "scan_id": scan_id,
            "error": error
        })

    async def broadcast_notification(self, user_id: str, notification: dict):
        await self.broadcast_to_user(user_id, {
            "type": "notification",
            **notification
        })

    async def broadcast_system_metrics(self, metrics: dict):
        await self.broadcast("system_monitor", {
            "type": "system_metrics",
            **metrics
        })

    def get_connection_count(self, channel: str) -> int:
        return len(self.connections.get(channel, set()))

    def get_total_connections(self) -> int:
        return sum(len(conns) for conns in self.connections.values())