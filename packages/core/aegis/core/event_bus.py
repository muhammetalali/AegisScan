"""ناقل الأحداث المركزي — Central Async Event Bus (Pub/Sub).

القلب النابض للنظام: جميع المكونات تتواصل حصراً عبر هذا الناقل
(فصل تام — Strict Decoupling). لا يُسمح بالاتصال المباشر بين المحركات.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("aegis.event_bus")

Subscriber = Callable[["Event"], Awaitable[None]]


@dataclass(frozen=True)
class Event:
    """حدث واحد يمر عبر الناقل."""

    topic: str
    payload: dict
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "system"
    correlation_id: Optional[str] = None


class EventBus:
    """ناشر/مشترك غير متزامن مع طابور معالجة داخلي.

    المواضيع المعتمدة في Aegis:
        scan.started, scan.progress, scan.finished,
        evidence.new, finding.new,
        exploit.run, exploit.success,
        remediate.apply, remediate.done,
        alert.critical
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Subscriber]] = {}
        self._queue: "asyncio.Queue[Event]" = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self._processed = 0
        self._errors = 0

    def subscribe(self, topic: str, subscriber: Subscriber) -> None:
        """تسجيل مشترك على موضوع معين."""
        self._subscribers.setdefault(topic, []).append(subscriber)
        logger.debug("Subscribed to '%s' (total=%d)", topic, len(self._subscribers[topic]))

    def unsubscribe(self, topic: str, subscriber: Subscriber) -> None:
        """إلغاء تسجيل مشترك."""
        subs = self._subscribers.get(topic)
        if subs and subscriber in subs:
            subs.remove(subscriber)

    async def publish(
        self,
        topic: str,
        payload: dict,
        source: str = "system",
        correlation_id: Optional[str] = None,
    ) -> Event:
        """نشر حدث جديد إلى الطابور (غير حاجب)."""
        event = Event(
            topic=topic, payload=payload,
            source=source, correlation_id=correlation_id,
        )
        await self._queue.put(event)
        logger.debug("Published event %s on topic '%s'", event.id, topic)
        return event

    async def wait_until_idle(self) -> None:
        """ينتظر حتى تُعالج جميع الأحداث المعلقة في الطابور."""
        await self._queue.join()

    async def start(self) -> None:
        """تشغيل عامل المعالجة في الخلفية."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._consume())
        logger.info("EventBus started")

    async def stop(self, drain: bool = True) -> None:
        """إيقاف الناقل مع تفريغ الطابور أولاً إذا طُلب ذلك."""
        self._running = False
        if drain:
            await self._queue.join()
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("EventBus stopped")

    async def _consume(self) -> None:
        """حلقة العامل: تعالج كل الأحداث حتى بعد إشارة التوقف (Drain)."""
        while self._running or not self._queue.empty():
            try:
                event = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                if not self._running:
                    return
                await asyncio.sleep(0.05)
                continue
            try:
                await self._dispatch(event)
                self._processed += 1
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: Event) -> None:
        """تسليم الحدث لكل المشتركين مع عزل أخطاء كل مشترك."""
        for subscriber in list(self._subscribers.get(event.topic, [])):
            try:
                await subscriber(event)
            except Exception:
                self._errors += 1
                logger.exception(
                    "Subscriber failed on topic '%s' (event %s)", event.topic, event.id
                )

    @property
    def stats(self) -> Dict[str, int]:
        """إحصائيات الناقل (معالجة/أخطاء/طابور/مشتركون)."""
        return {
            "processed": self._processed,
            "errors": self._errors,
            "queue_size": self._queue.qsize(),
            "topics": len(self._subscribers),
            "subscribers": sum(len(s) for s in self._subscribers.values()),
        }
