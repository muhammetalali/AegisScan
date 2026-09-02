from __future__ import annotations

import asyncio
import json
import logging
from typing import Awaitable, Callable

import redis.asyncio as redis_async

from ..core.config import settings
from .workflow_events import CHANNEL

logger = logging.getLogger(__name__)


class WorkflowLiveBridge:
    def __init__(self, broadcast: Callable[[dict], Awaitable[None]]) -> None:
        self._broadcast = broadcast
        self._task: asyncio.Task | None = None
        self._client: redis_async.Redis | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        self._client = redis_async.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        self._task = asyncio.create_task(self._run(), name="workflow-live-bridge")

    async def _run(self) -> None:
        assert self._client is not None
        pubsub = self._client.pubsub()
        try:
            await pubsub.subscribe(CHANNEL)
            while not self._stop.is_set():
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if not message:
                    await asyncio.sleep(0.05)
                    continue
                try:
                    payload = json.loads(message["data"])
                    await self._broadcast(payload)
                except (TypeError, json.JSONDecodeError) as exc:
                    logger.warning("Invalid workflow event payload: %s", exc)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Workflow Redis bridge stopped: %s", exc)
        finally:
            try:
                await pubsub.unsubscribe(CHANNEL)
                await pubsub.aclose()
                await self._client.aclose()
            except Exception:
                pass

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
