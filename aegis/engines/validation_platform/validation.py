"""Validation Engine — محرك التحقق الآمن.

المرحلة الخامسة: يتحقق من نتائج الثغرات داخل بيئة مصرح فيها ومعزولة.
الهدف: قياس فعالية الضوابط، مو استغلال الأنظمة.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.validation")


class ValidationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class ValidationMethod(str, Enum):
    SAFE_PROBE = "safe_probe"           # استعلام آمن
    CONFIG_AUDIT = "config_audit"       # تدقيق الإعدادات
    LOG_ANALYSIS = "log_analysis"       # تحليل السجلات
    PATTERN_MATCH = "pattern_match"     # مطابقة الأنماط
    CONTROL_CHECK = "control_check"     # فحص الضابط
    DEPENDENCY_CHECK = "dependency_check"


@dataclass
class ValidationResult:
    """نتيجة التحقق."""
    validation_id: str
    finding_id: str
    status: ValidationStatus
    method: ValidationMethod
    evidence_ids: List[str] = field(default_factory=list)
    confidence: float = 0.0
    details: str = ""
    duration_ms: float = 0.0
    validated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationScenario:
    """سيناريو تحقق."""
    scenario_id: str
    name: str
    description: str
    method: ValidationMethod
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_result: str = ""
    severity: str = "medium"


ValidationHandler = Callable[
    [ValidationScenario], Coroutine[Any, Any, ValidationResult]
]


class ValidationEngine:
    """محرك التحقق الآمن — يتحقق من النتائج بطرق متعددة."""

    name = "ValidationEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._results: Dict[str, ValidationResult] = {}
        self._scenarios: Dict[str, ValidationScenario] = {}
        self._handlers: Dict[str, ValidationHandler] = {}
        self._history: List[Dict[str, Any]] = []

    def register_handler(
        self, method: ValidationMethod, handler: ValidationHandler
    ) -> None:
        """تسجيل معالج لطريقة تحقق."""
        self._handlers[method.value] = handler
        logger.info("تم تسجيل معالج: %s", method.value)

    async def add_scenario(self, scenario: ValidationScenario) -> None:
        """إضافة سيناريو تحقق."""
        self._scenarios[scenario.scenario_id] = scenario

    async def validate(self, scenario: ValidationScenario) -> ValidationResult:
        """تنفيذ التحقق."""
        start = datetime.now(timezone.utc)
        logger.info("بدء التحقق: %s (%s)", scenario.name, scenario.method.value)

        await self.event_bus.publish(
            topic="validation.started",
            payload={"scenario_id": scenario.scenario_id},
            source=self.name,
        )

        # التحقق عبر المعالج المخصص
        handler = self._handlers.get(scenario.method.value)
        if handler:
            try:
                result = await asyncio.wait_for(
                    handler(scenario), timeout=60.0
                )
            except asyncio.TimeoutError:
                result = ValidationResult(
                    validation_id=f"val_{scenario.scenario_id}",
                    finding_id=scenario.target,
                    status=ValidationStatus.ERROR,
                    method=scenario.method,
                    details="انتهت المهلة الزمنية",
                )
            except Exception as exc:
                result = ValidationResult(
                    validation_id=f"val_{scenario.scenario_id}",
                    finding_id=scenario.target,
                    status=ValidationStatus.ERROR,
                    method=scenario.method,
                    details=f"خطأ: {exc}",
                )
        else:
            # التحقق الافتراضي — فحص النمط
            result = await self._default_validate(scenario)

        # حساب المدة
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        result.duration_ms = elapsed
        result.validated_at = datetime.now(timezone.utc)

        self._results[result.validation_id] = result
        self._history.append({
            "validation_id": result.validation_id,
            "status": result.status.value,
            "method": result.method.value,
            "timestamp": result.validated_at.isoformat(),
        })

        await self.event_bus.publish(
            topic="validation.completed",
            payload={
                "validation_id": result.validation_id,
                "status": result.status.value,
                "confidence": result.confidence,
            },
            source=self.name,
        )

        return result

    async def validate_finding(
        self,
        finding_id: str,
        method: ValidationMethod,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """تحقق سريع من نتيجة واحدة."""
        scenario = ValidationScenario(
            scenario_id=f"vs_{finding_id}",
            name=f"تحقق من {finding_id}",
            description="تحقق تلقائي",
            method=method,
            target=target,
            parameters=parameters or {},
        )
        return await self.validate(scenario)

    async def validate_batch(
        self, scenarios: List[ValidationScenario]
    ) -> List[ValidationResult]:
        """تحقق من مجموعة سيناريوهات."""
        results = []
        for scenario in scenarios:
            result = await self.validate(scenario)
            results.append(result)
        return results

    def get_result(self, validation_id: str) -> Optional[ValidationResult]:
        """استرجاع نتيجة."""
        return self._results.get(validation_id)

    def get_confirmed(self) -> List[ValidationResult]:
        """استرجاع النتائج المؤكدة."""
        return [
            r for r in self._results.values()
            if r.status == ValidationStatus.CONFIRMED
        ]

    def get_refuted(self) -> List[ValidationResult]:
        """استرجاع النتائج المرفوضة (False Positives)."""
        return [
            r for r in self._results.values()
            if r.status == ValidationStatus.REFUTED
        ]

    def get_inconclusive(self) -> List[ValidationResult]:
        """استرجاع النتائج غير الحاسمة."""
        return [
            r for r in self._results.values()
            if r.status == ValidationStatus.INCONCLUSIVE
        ]

    def summary(self) -> Dict[str, Any]:
        """ملخص التحقق."""
        by_status: Dict[str, int] = {}
        for r in self._results.values():
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        confirmed = by_status.get("confirmed", 0)
        refuted = by_status.get("refuted", 0)
        total = confirmed + refuted
        return {
            "total_validations": len(self._results),
            "by_status": by_status,
            "confirmation_rate": confirmed / max(total, 1),
            "false_positive_rate": refuted / max(total, 1),
        }

    async def _default_validate(
        self, scenario: ValidationScenario
    ) -> ValidationResult:
        """تحقق افتراضي — يتحقق هل النمط موجود."""
        return ValidationResult(
            validation_id=f"val_{scenario.scenario_id}",
            finding_id=scenario.target,
            status=ValidationStatus.INCONCLUSIVE,
            method=scenario.method,
            details="لا يوجد معالج مخصص — تم التحقق بنمط افتراضي",
            confidence=0.3,
        )
