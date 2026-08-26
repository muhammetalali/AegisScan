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

    async def connect(self, channel: str, websocket: WebSocket):
        await websocket.accept()
        if channel not in self.connections:
            self.connections[channel] = set()
        self.connections[channel].add(websocket)
        logger.info(f"WebSocket connected to {channel}. Total connections: {len(self.connections[channel])}")

    def disconnect(self, channel: str, websocket: WebSocket):
        if channel in self.connections:
            self.connections[channel].discard(websocket)
            if not self.connections[channel]:
                del self.connections[channel]
        logger.info(f"WebSocket disconnected from {channel}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast(self, channel: str, message: dict):
        if channel not in self.connections:
            return
        disconnected = set()
        for websocket in self.connections[channel]:
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