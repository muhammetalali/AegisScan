"""Execution Controller — متحكم التنفيذ.

ينفّذ الإجراءات حسب الخطة مع مراقبة المهلة وال潘dlimit.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.engines.validation.planner import (
    ExecutionPlan,
    PlannedAction,
    PlanStatus,
)

logger = logging.getLogger("aegis.validation.controller")


@dataclass
class ActionResult:
    """نتيجة تنفيذ إجراء واحد."""
    action_id: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class ExecutionRecord:
    """سجل تنفيذ خطة كاملة."""
    plan_id: str
    results: List[ActionResult] = field(default_factory=list)
    total_duration: float = 0.0
    success_count: int = 0
    failure_count: int = 0


class ExecutionController:
    """متحكم التنفيذ — ينفّذ الإجراءات ويُسجّل النتائج."""

    name = "ExecutionController"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._action_handlers: Dict[str, Callable[..., Coroutine]] = {}

    def register_handler(
        self, action_type: str, handler: Callable[..., Coroutine]
    ) -> None:
        """تسجيل معالج لنوع إجراء معين."""
        self._action_handlers[action_type] = handler
        logger.info("معالج مسجل: %s", action_type)

    async def execute_plan(
        self, plan: ExecutionPlan
    ) -> ExecutionRecord:
        """تنفيذ خطة كاملة."""
        record = ExecutionRecord(plan_id=plan.plan_id)
        start_time = time.monotonic()

        plan.status = PlanStatus.EXECUTING

        for action in plan.actions:
            result = await self._execute_action(action)
            record.results.append(result)

            if result.success:
                record.success_count += 1
                # تحديث الخطة
                plan.metadata.setdefault("completed_actions", set()).add(
                    action.action_id
                )
            else:
                record.failure_count += 1
                # إيقاف في حالة فشل حرج
                if action.level.value in ("destructive", "execute"):
                    logger.error(
                        "فشل حرج في %s — إيقاف الخطة", action.action_id
                    )
                    plan.status = PlanStatus.FAILED
                    break

        record.total_duration = time.monotonic() - start_time

        if plan.status == PlanStatus.EXECUTING:
            plan.status = PlanStatus.COMPLETED

        # نشر سجل التنفيذ
        await self.event_bus.publish(
            topic="execution.completed",
            payload={
                "plan_id": plan.plan_id,
                "success": record.success_count,
                "failure": record.failure_count,
                "duration": record.total_duration,
            },
            source=self.name,
        )

        logger.info(
            "خطة %s: %d نجاح / %d فشل (%.2f ثانية)",
            plan.plan_id, record.success_count,
            record.failure_count, record.total_duration,
        )
        return record

    async def _execute_action(self, action: PlannedAction) -> ActionResult:
        """تنفيذ إجراء واحد مع مهلة."""
        start = time.monotonic()
        handler = self._action_handlers.get(action.action_type)

        if not handler:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=f"لا يوجد معالج لنوع '{action.action_type}'",
                duration_seconds=time.monotonic() - start,
            )

        try:
            result = await asyncio.wait_for(
                handler(action.target, action.parameters),
                timeout=action.timeout_seconds,
            )
            return ActionResult(
                action_id=action.action_id,
                success=True,
                result=result,
                duration_seconds=time.monotonic() - start,
            )
        except asyncio.TimeoutError:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=f"انتهت المهلة ({action.timeout_seconds} ثانية)",
                duration_seconds=time.monotonic() - start,
            )
        except Exception as exc:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=str(exc),
                duration_seconds=time.monotonic() - start,
            )
