from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Set

import redis.asyncio as redis_async
from fastapi import WebSocket
from starlette.websockets import WebSocketState

from ..core.config import settings

logger = logging.getLogger(__name__)


class WebSocketManager:
    """WebSocket registry with Redis-backed cross-process event delivery."""

    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.user_connections: Dict[str, Set[WebSocket]] = {}
        self._redis_tasks: Dict[WebSocket, asyncio.Task] = {}

    async def connect(self, channel: str, websocket: WebSocket, subprotocol: str | None = None):
        if websocket.client_state == WebSocketState.CONNECTING:
            negotiated_subprotocol = None
            if subprotocol:
                offered = {
                    part.strip()
                    for part in websocket.headers.get("sec-websocket-protocol", "").split(",")
                    if part.strip()
                }
                if subprotocol in offered:
                    negotiated_subprotocol = subprotocol
            await websocket.accept(subprotocol=negotiated_subprotocol)
        self.connections.setdefault(channel, set()).add(websocket)
        logger.info("WebSocket connected to %s. Total connections: %s", channel, len(self.connections[channel]))
        self._ensure_redis_stream(websocket, channel)

    def _ensure_redis_stream(self, websocket: WebSocket, channel: str) -> None:
        if websocket in self._redis_tasks:
            return
        self._redis_tasks[websocket] = asyncio.create_task(self._redis_stream(websocket, channel))

    async def _redis_stream(self, websocket: WebSocket, channel: str) -> None:
        client = None
        pubsub = None
        try:
            client = redis_async.Redis.from_url(settings.REDIS_URL, decode_responses=True, health_check_interval=30)
            pubsub = client.pubsub()
            await pubsub.subscribe(f"aegis:scan-events:{channel}", f"aegis:validation-events:{channel}")
            while websocket.client_state == WebSocketState.CONNECTED:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if not message or message.get("type") != "message":
                    await asyncio.sleep(0.05)
                    continue
                raw = message.get("data")
                try:
                    payload = json.loads(raw) if isinstance(raw, str) else raw
                except (TypeError, json.JSONDecodeError):
                    logger.warning("Ignoring malformed Redis event on WebSocket channel %s", channel)
                    continue
                if isinstance(payload, dict):
                    try:
                        await websocket.send_json(payload)
                    except Exception:
                        return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Redis WebSocket event stream failed for channel %s", channel)
        finally:
            if pubsub is not None:
                try:
                    await pubsub.close()
                except Exception:
                    pass
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass

    def disconnect(self, channel: str, websocket: WebSocket):
        sockets = self.connections.get(channel)
        if sockets is not None:
            sockets.discard(websocket)
            if not sockets:
                self.connections.pop(channel, None)
        still_registered = any(websocket in sockets for sockets in self.connections.values())
        if not still_registered:
            task = self._redis_tasks.pop(websocket, None)
            if task and not task.done():
                task.cancel()
        logger.info("WebSocket disconnected from %s", channel)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        try:
            await websocket.send_json(message)
        except Exception as exc:
            logger.error("Error sending personal message: %s", exc)

    async def broadcast(self, channel: str, message: dict):
        sockets = list(self.connections.get(channel, set()))
        disconnected = set()
        for websocket in sockets:
            try:
                await websocket.send_json(message)
            except Exception as exc:
                logger.error("Error broadcasting to %s: %s", channel, exc)
                disconnected.add(websocket)
        for websocket in disconnected:
            self.disconnect(channel, websocket)

    async def broadcast_to_user(self, user_id: str, message: dict):
        await self.broadcast(f"user_{user_id}", message)

    async def broadcast_scan_progress(self, scan_id: str, progress_data: dict):
        await self.broadcast(f"scan_{scan_id}", {"type": "scan_progress", "scan_id": scan_id, **progress_data})

    async def broadcast_scan_completed(self, scan_id: str, result: dict):
        await self.broadcast(f"scan_{scan_id}", {"type": "scan_completed", "scan_id": scan_id, "result": result})

    async def broadcast_scan_error(self, scan_id: str, error: str):
        await self.broadcast(f"scan_{scan_id}", {"type": "scan_error", "scan_id": scan_id, "error": error})

    async def broadcast_notification(self, user_id: str, notification: dict):
        await self.broadcast_to_user(user_id, {"type": "notification", **notification})

    async def broadcast_system_metrics(self, metrics: dict):
        await self.broadcast("system_monitor", {"type": "system_metrics", **metrics})

    def get_connection_count(self, channel: str) -> int:
        return len(self.connections.get(channel, set()))

    def get_total_connections(self) -> int:
        return sum(len(conns) for conns in self.connections.values())
