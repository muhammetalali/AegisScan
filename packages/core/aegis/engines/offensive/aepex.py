"""AePEX — منسق الطبقة 3: يدير الاختبار داخل التوأم فقط.

ضوابط صارمة:
1. قائمة سماح للأهداف (allowed_target_prefixes) — استهداف أي شيء آخر مرفوض.
2. كل عملية تُسجَّل في AuditLogger إلزامياً.
3. لا وحدات مسجلة افتراضياً — تُضاف فوق أدوات اختبار معتمدة لاحقاً.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple, Type

from aegis.core.audit_logger import AuditLogger
from aegis.engines.offensive.base_module import BaseTestModule, TestResult
from aegis.models.finding import Severity
from aegis.engines.offensive.twin import DigitalTwin
from aegis.engines.offensive.verifier import VerificationEngine

logger = logging.getLogger("aegis.offensive.aepex")


class AePEX:
    """المنسق التنفيذي للطبقة الهجومية/الاختبارية داخل التوأم."""

    def __init__(
        self,
        twin: DigitalTwin,
        audit_logger: AuditLogger,
        allowed_target_prefixes: Optional[Tuple[str, ...]] = None,
    ) -> None:
        self.twin = twin
        self.audit = audit_logger
        self.verifier = VerificationEngine()
        self._modules: Dict[str, Type[BaseTestModule]] = {}

        # قائمة السماح الافتراضية: هدف التوأم نفسه حصراً
        self.allowed_target_prefixes = allowed_target_prefixes or (
            twin.config.test_base_url,
        )

    # ─── التسجيل ──────────────────────────────────────────────

    def register_module(self, vuln_type: str, module_class: Type[BaseTestModule]) -> None:
        """تسجيل وحدة اختبار لنوع ثغرة محدد."""
        self._modules[vuln_type.lower()] = module_class
        logger.info("وحدة مسجلة: %s → %s", vuln_type, module_class.__name__)

    @property
    def registered(self) -> Dict[str, str]:
        return {k: v.__name__ for k, v in self._modules.items()}

    # ─── بوابة الأهداف ────────────────────────────────────────

    def _target_allowed(self, target: str) -> bool:
        t = (target or "").strip().lower()
        if not t:
            return False
        return any(t.startswith(p.lower()) for p in self.allowed_target_prefixes)

    # ─── التنفيذ ──────────────────────────────────────────────

    def execute_test(
        self,
        finding: Dict[str, Any],
        user_id: str,
    ) -> Optional[TestResult]:
        """اختبار ثغرة مؤكدة داخل التوأم مع تدقيق كامل.

        Returns:
            TestResult أو None عند الرفض المسبق.
        """
        vuln_type = str(finding.get("category", "")).lower()
        target = str(finding.get("target") or finding.get("attack_path") or "")
        scan_id = finding.get("scan_id", "?")

        def _audit(action: str, result: str, **extra) -> None:
            self.audit.log(
                user_id=user_id, action=action, target=target or "(none)",
                result=result,
                extra={"scan_id": scan_id, "vuln_type": vuln_type, **extra},
            )

        # بوابة 1: الهدف ضمن قائمة السماح؟
        if not self._target_allowed(target):
            logger.error("هدف خارج قائمة السماح: %s", target)
            _audit("test.rejected", "target_not_allowed")
            return None

        # بوابة 2: التوأم جاهز ومعزول؟
        if not self.twin.is_safe_to_test:
            _audit("test.rejected", "twin_not_ready")
            return None

        # بوابة 3: وحدة مسجلة لهذا النوع؟
        module_class = self._modules.get(vuln_type)
        if module_class is None:
            logger.warning("لا وحدة مسجلة لنوع: %s", vuln_type)
            _audit("test.rejected", "no_module")
            return None

        module = module_class(
            twin=self.twin,
            parameters={
                "finding": finding,
                "target": target,
                **(finding.get("parameters") or {}),
            },
        )
        _audit("test.started", "in_progress", module=module.name)

        result = module.execute()

        # تأكيد إضافي عبر المحرك المستقل
        if result.success and not self.verifier.verify(module, result):
            result.success = False
            result.verified = False
            result.proof += " | فشل تأكيد VerificationEngine"

        _audit(
            "test.completed",
            "success" if result.success else "failed",
            module=module.name,
            verified=result.verified,
            risk=result.risk_level.value if isinstance(result.risk_level, Severity) else str(result.risk_level),
        )

        logger.info(
            "نتيجة %s على %s: success=%s verified=%s",
            module.name, target, result.success, result.verified,
        )
        return result
