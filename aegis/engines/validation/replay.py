"""Replay Engine — محرك إعادة التشغيل.

يمكن إعادة تشغيل إجراءات مسجلة للتحقق من النتائج أو
استنساخ مشاكل سابقة.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.engines.validation.recorder import ActionRecorder

logger = logging.getLogger("aegis.validation.replay")


@dataclass
class ReplayResult:
    """نتيجة إعادة التشغيل."""
    original_action_id: str
    replayed: bool
    matches: Optional[bool] = None  # هل تطابقت النتيجة؟
    original_result: Any = None
    replay_result: Any = None
    difference: Optional[str] = None


class ReplayEngine:
    """محرك إعادة التشغيل — يعيد تنفيذ إجراءات مسجلة للتحقق."""

    name = "ReplayEngine"

    def __init__(
        self,
        event_bus: EventBus,
        recorder: ActionRecorder,
    ) -> None:
        self.event_bus = event_bus
        self.recorder = recorder
        self._action_handlers: Dict[str, Callable[..., Coroutine]] = {}

    def register_handler(
        self, action_type: str, handler: Callable[..., Coroutine]
    ) -> None:
        """تسجيل معالج لإعادة التشغيل."""
        self._action_handlers[action_type] = handler

    async def replay_action(
        self,
        action_id: str,
        verify: bool = True,
    ) -> ReplayResult:
        """إعادة تشغيل إجراء واحد."""
        # استرجاع الإجراء الأصلي
        log = self.recorder.get_log(action_id=action_id, limit=1)
        if not log:
            return ReplayResult(
                original_action_id=action_id,
                replayed=False,
                difference="الإجراء غير موجود في السجل",
            )

        entry = log[0]
        action_type = entry["action_type"]
        target = entry["target"]
        parameters = (
            __import__("json").loads(entry["parameters"])
            if entry["parameters"]
            else {}
        )

        handler = self._action_handlers.get(action_type)
        if not handler:
            return ReplayResult(
                original_action_id=action_id,
                replayed=False,
                difference=f"لا يوجد معالج لإعادة تشغيل '{action_type}'",
            )

        # إعادة التنفيذ
        try:
            new_result = await handler(target, parameters)
        except Exception as exc:
            return ReplayResult(
                original_action_id=action_id,
                replayed=False,
                original_result=entry["result"],
                difference=f"خطأ في إعادة التشغيل: {exc}",
            )

        # المقارنة
        matches = None
        diff = None
        if verify:
            original_result = entry["result"]
            matches, diff = self._compare_results(original_result, new_result)

        # تسجيل إعادة التشغيل
        await self.recorder.record_action(
            action_id=f"replay_{action_id}",
            plan_id=None,
            action_type=f"replay.{action_type}",
            level="read",
            target=target or "",
            parameters=parameters,
            result=new_result,
            success=True,
        )

        result = ReplayResult(
            original_action_id=action_id,
            replayed=True,
            matches=matches,
            original_result=entry["result"],
            replay_result=new_result,
            difference=diff,
        )

        await self.event_bus.publish(
            topic="replay.completed",
            payload={
                "original_action_id": action_id,
                "matches": matches,
                "difference": diff,
            },
            source=self.name,
        )

        logger.info(
            "إعادة تشغيل %s: %s",
            action_id, "تطابق" if matches else "اختلاف",
        )
        return result

    async def replay_plan(
        self,
        plan_id: str,
        verify: bool = True,
    ) -> List[ReplayResult]:
        """إعادة تشغيل كل إجراءات خطة معينة."""
        log = self.recorder.get_log(plan_id=plan_id)
        results = []
        for entry in log:
            if entry.get("action_id", "").startswith("replay_"):
                continue
            result = await self.replay_action(
                entry["action_id"], verify=verify
            )
            results.append(result)
        return results

    @staticmethod
    def _compare_results(
        original: Any, new: Any
    ) -> tuple[bool, Optional[str]]:
        """مقارنة نتيجتين."""
        if original is None and new is None:
            return True, None
        if original is None or new is None:
            return False, f"أحدهما None: original={original}, new={new}"

        # مقارنة كـ JSON
        import json

        # محاولة تحويل كليهما إلى dict
        def _to_dict(val: Any) -> Any:
            if isinstance(val, str):
                try:
                    return json.loads(val)
                except Exception:
                    return val
            return val

        orig_val = _to_dict(original)
        new_val = _to_dict(new)

        try:
            orig_str = json.dumps(orig_val, sort_keys=True, default=str)
            new_str = json.dumps(new_val, sort_keys=True, default=str)
            if orig_str == new_str:
                return True, None
            return False, f"النتائج مختلفة: {orig_str[:100]} ≠ {new_str[:100]}"
        except Exception:
            if str(original) == str(new):
                return True, None
            return False, f"النتائج مختلفة: {str(original)[:100]} ≠ {str(new)[:100]}"
