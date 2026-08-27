"""Remediation Verifier — محقق الإصلاح.

يتحقق من أن الإصلاح لم يكسر الوظائف الأساسية.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.remediation import Remediation, RemediationTestResult

logger = logging.getLogger("aegis.remediation.verifier")


class RemediationVerifier:
    """محقق الإصلاح — يختبر أن الإصلاح آمن وصحيح."""

    name = "RemediationVerifier"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._checks: List[Callable[..., Coroutine]] = []

    def register_check(
        self, check: Callable[..., Coroutine]
    ) -> None:
        """تسجيل فحص."""
        self._checks.append(check)

    async def verify(
        self,
        remediation: Remediation,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """التحقق من إصلاح.

        Returns:
            {
                "remediation_id": str,
                "safe": bool,
                "checks": [{ "name": str, "passed": bool, "details": str }],
                "recommendation": str,
            }
        """
        results: List[Dict[str, Any]] = []

        # فحص 1: هل الإصلاح مكتمل الاختبارات؟
        results.append(self._check_test_status(remediation))

        # فحص 2: هل الإصلاح موثوق بما يكفي؟
        results.append(self._check_confidence(remediation))

        # فحص 3: فحوصات مخصصة
        for check_fn in self._checks:
            try:
                result = await check_fn(remediation, context)
                results.append(result)
            except Exception as exc:
                results.append({
                    "name": check_fn.__name__,
                    "passed": False,
                    "details": str(exc),
                })

        all_passed = all(r["passed"] for r in results)
        recommendation = self._generate_recommendation(results, remediation)

        verification = {
            "remediation_id": remediation.id,
            "safe": all_passed,
            "checks": results,
            "recommendation": recommendation,
        }

        await self.event_bus.publish(
            topic="remediation.verified",
            payload=verification,
            source=self.name,
        )

        logger.info(
            "تحقق %s: %s (%d/%d فحوصات نجحت)",
            remediation.id,
            "آمن" if all_passed else "غير آمن",
            sum(1 for r in results if r["passed"]),
            len(results),
        )
        return verification

    @staticmethod
    def _check_test_status(remediation: Remediation) -> Dict[str, Any]:
        """فحص حالة الاختبارات."""
        if not remediation.test_results:
            return {
                "name": "test_status",
                "passed": False,
                "details": "لم تُجرَ اختبارات بعد",
            }
        passed = sum(1 for t in remediation.test_results if t.passed)
        total = len(remediation.test_results)
        return {
            "name": "test_status",
            "passed": passed == total,
            "details": f"{passed}/{total} اختبارات نجحت",
        }

    @staticmethod
    def _check_confidence(remediation: Remediation) -> Dict[str, Any]:
        """فحص ثقة الإصلاح."""
        threshold = 0.6
        passed = remediation.confidence >= threshold
        return {
            "name": "confidence",
            "passed": passed,
            "details": (
                f"ثقة الإصلاح: {remediation.confidence:.2f} "
                f"{'(كافية)' if passed else '(غير كافية)'}"
            ),
        }

    @staticmethod
    def _generate_recommendation(
        checks: List[Dict[str, Any]],
        remediation: Remediation,
    ) -> str:
        """توليد توصية بناءً على الفحوصات."""
        failed = [c for c in checks if not c["passed"]]
        if not failed:
            return "الإصلاح آمن — يمكن تطبيقه."
        names = ", ".join(c["name"] for c in failed)
        return f"الإصلاح غير آمن — فشل في: {names}. يُنصح بالمراجعة اليدوية."
