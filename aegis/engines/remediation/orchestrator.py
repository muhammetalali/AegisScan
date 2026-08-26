"""Remediation Orchestrator — منسق الإصلاح.

ينسق عملية الإصلاح الكاملة: توليد → اختبار → موافقة → تطبيق → تحقق.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.finding import Finding, Severity
from aegis.models.remediation import (
    Remediation,
    RemediationMethod,
    RemediationStatus,
    RemediationTestResult,
)

logger = logging.getLogger("aegis.remediation.orchestrator")


class RemediationOrchestrator:
    """منسق الإصلاح — يدير دورة حياة الإصلاح من البداية للنهاية."""

    name = "RemediationOrchestrator"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._remediations: Dict[str, Remediation] = {}
        self._generators: Dict[str, Callable[..., Coroutine]] = {}
        self._testers: List[Callable[..., Coroutine]] = []

    def register_generator(
        self, name: str, gen: Callable[..., Coroutine]
    ) -> None:
        """تسجيل مولّد إصلاحات (نمطي أو LLM)."""
        self._generators[name] = gen

    def register_tester(
        self, tester: Callable[..., Coroutine]
    ) -> None:
        """تسجيل مختبر إصلاحات."""
        self._testers.append(tester)

    async def generate_remediation(
        self,
        finding: Finding,
        method: RemediationMethod = RemediationMethod.PATTERN_BASED,
        generator_name: str = "pattern",
    ) -> Optional[Remediation]:
        """توليد إصلاح لثغرة معينة."""
        generator = self._generators.get(generator_name)
        if not generator:
            logger.warning("لا يوجد مولّد '%s'", generator_name)
            return None

        try:
            result = await generator(finding)
        except Exception as exc:
            logger.error("فشل توليد الإصلاح: %s", exc)
            return None

        if not result or not result.get("patch"):
            return None

        remediation = Remediation(
            finding_id=finding.id,
            method=method,
            generated_patch=result["patch"],
            old_code_snippet=result.get("old_code"),
            file_path=result.get("file_path"),
            line_start=result.get("line_start"),
            line_end=result.get("line_end"),
            confidence=result.get("confidence", 0.5),
        )

        self._remediations[remediation.id] = remediation

        await self.event_bus.publish(
            topic="remediation.generated",
            payload=remediation.to_dict(),
            source=self.name,
        )

        logger.info(
            "إصلاح مولّد: %s للثغرة %s (ثقة %.2f)",
            remediation.id, finding.id, remediation.confidence,
        )
        return remediation

    async def test_remediation(
        self, remediation_id: str
    ) -> Remediation:
        """اختبار إصلاح في بيئة معزولة."""
        rem = self._remediations.get(remediation_id)
        if not rem:
            raise ValueError(f"إصلاح غير موجود: {remediation_id}")

        rem.status = RemediationStatus.TESTING

        test_results: List[RemediationTestResult] = []
        for tester in self._testers:
            try:
                result = await tester(rem)
                test_results.append(result)
            except Exception as exc:
                test_results.append(RemediationTestResult(
                    test_type="error",
                    passed=False,
                    details=str(exc),
                ))

        rem.test_results = test_results

        if rem.all_tests_passed:
            rem.status = RemediationStatus.TEST_PASSED
        else:
            rem.status = RemediationStatus.TEST_FAILED

        await self.event_bus.publish(
            topic="remediation.tested",
            payload={
                "remediation_id": rem.id,
                "status": rem.status.value,
                "tests_passed": sum(1 for t in test_results if t.passed),
                "tests_total": len(test_results),
            },
            source=self.name,
        )

        logger.info(
            "اختبار %s: %s (%d/%d نجاح)",
            rem.id, rem.status.value,
            sum(1 for t in test_results if t.passed),
            len(test_results),
        )
        return rem

    async def approve_remediation(
        self, remediation_id: str
    ) -> Remediation:
        """الموافقة على إصلاح."""
        rem = self._remediations.get(remediation_id)
        if not rem:
            raise ValueError(f"إصلاح غير موجود: {remediation_id}")

        if rem.status != RemediationStatus.TEST_PASSED:
            rem.status = RemediationStatus.PENDING_APPROVAL

        rem.status = RemediationStatus.APPROVED

        await self.event_bus.publish(
            topic="remediation.approved",
            payload=rem.to_dict(),
            source=self.name,
        )

        logger.info("تمت الموافقة على %s", rem.id)
        return rem

    async def apply_remediation(
        self, remediation_id: str
    ) -> Remediation:
        """تطبيق إصلاح (町の実際ية — هنا فقط نُحدّث الحالة)."""
        rem = self._remediations.get(remediation_id)
        if not rem:
            raise ValueError(f"إصلاح غير موجود: {remediation_id}")

        if rem.status != RemediationStatus.APPROVED:
            logger.warning("لا يمكن تطبيق %s: الحالة %s", rem.id, rem.status.value)
            return rem

        rem.status = RemediationStatus.APPLIED

        await self.event_bus.publish(
            topic="remediation.applied",
            payload=rem.to_dict(),
            source=self.name,
        )

        logger.info("تم تطبيق %s", rem.id)
        return rem

    def get_remediation(self, remediation_id: str) -> Optional[Remediation]:
        """استرجاع إصلاح."""
        return self._remediations.get(remediation_id)

    def get_by_finding(self, finding_id: str) -> List[Remediation]:
        """استرجاع إصلاحات ثغرة معينة."""
        return [
            r for r in self._remediations.values()
            if r.finding_id == finding_id
        ]

    def summary(self) -> Dict[str, Any]:
        """ملخص الإصلاحات."""
        stats: Dict[str, int] = {}
        for rem in self._remediations.values():
            stats[rem.status.value] = stats.get(rem.status.value, 0) + 1
        return {
            "total": len(self._remediations),
            "by_status": stats,
        }
