"""Verification Engine — محرك التأكيد المزدوج (قاتل الإيجابيات الكاذبة)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from aegis.engines.offensive.base_module import BaseTestModule, TestResult

logger = logging.getLogger("aegis.offensive.verifier")


class VerificationEngine:
    """لا نتيجة تُقبل إلا بعد N عمليات تأكيد متتالية."""

    def __init__(self, required_confirmations: int = 2) -> None:
        if required_confirmations < 1:
            raise ValueError("required_confirmations >= 1")
        self.required_confirmations = required_confirmations
        self.log: List[Dict[str, Any]] = []

    def verify(self, module: BaseTestModule, original: TestResult) -> bool:
        """إعادة تشغيل الفحص الأولي عدة مرات؛ يجب نجاحها كلها."""
        if not original.success:
            return False

        confirmed = 0
        for attempt in range(1, self.required_confirmations + 1):
            ok = module.check_vulnerability()
            self.log.append({
                "module": module.name, "attempt": attempt, "result": ok,
            })
            if ok:
                confirmed += 1
            else:
                logger.warning("محاولة تأكيد %s/%s فشلت للوحدة %s",
                               attempt, self.required_confirmations, module.name)

        passed = confirmed == self.required_confirmations
        logger.info("التأكيد للوحدة %s: %s (%s/%s)",
                    module.name, passed, confirmed, self.required_confirmations)
        return passed

    def stats(self) -> Dict[str, Any]:
        return {
            "total_verifications": len(self.log),
            "passed": sum(1 for e in self.log if e["result"]),
            "required_each_result": self.required_confirmations,
        }
