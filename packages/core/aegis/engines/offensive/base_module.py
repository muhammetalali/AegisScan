"""القالب الأساسي لوحدات الاختبار داخل التوأم.

ملاحظة حدود واضحة: هذا الإطار التنظيمي فقط.
لا توجد هنا أي حمولات أو استغلالات — الوحدات الفعلية تُبنى لاحقاً
فوق أدوات اختبار معتمدة (sqlmap/nuclei) وتعمل داخل التوأم حصراً
على أهداف من قائمة السماح.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from aegis.core.exceptions import SafetyViolationError
from aegis.models.finding import Severity
from aegis.engines.offensive.twin import DigitalTwin

logger = logging.getLogger("aegis.offensive.base_module")


class TestResult(BaseModel):
    """نتيجة تنفيذ وحدة اختبار واحدة."""

    # This is a result model, not a pytest test class.
    __test__ = False

    success: bool
    proof: str
    risk_level: Severity = Severity.INFO
    module_name: str = ""
    target: str = ""
    verified: bool = Field(
        default=False,
        description="هل أكّدت إعادة التنفيذ النتيجة؟ (قاتل الإيجابيات الكاذبة)",
    )
    execution_time_ms: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class BaseTestModule(ABC):
    """كل وحدة اختبار ترث من هنا — البوابات الأمنية مدمجة وإلزامية."""

    def __init__(
        self,
        twin: DigitalTwin,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.twin = twin
        self.parameters = parameters or {}
        self._aborted = False

    # ─── خصائص إلزامية ────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """اسم فريد للوحدة."""
        ...

    @property
    @abstractmethod
    def vuln_type(self) -> str:
        """نوع الثغرة المستهدفة (يطابق category في Finding)."""
        ...

    @property
    @abstractmethod
    def target_service(self) -> str:
        """اسم الخدمة داخل الـ compose التي ستُنفَّذ ضدها الفحوصات."""
        ...

    # ─── الدوال المطلوبة من الوحدة ────────────────────────────

    @abstractmethod
    def check_vulnerability(self) -> bool:
        """فحص أولي غير مدمِّر داخل التوأم."""

    @abstractmethod
    def _run_test(self) -> TestResult:
        """جسم الاختبار — يُنفَّذ بعد اجتياز كل البوابات فقط."""

    # ─── نقطة الدخول المحمية ──────────────────────────────────

    def execute(self) -> TestResult:
        """تنفيذ بثلاث بوابات أمنية إلزامية قبل جسم الاختبار."""
        base = dict(module_name=self.name)

        # بوابة 1: Kill Switch
        if self._aborted or self.twin._aborted:
            return TestResult(success=False,
                              proof="إيقاف فوري مفعل", **base)

        # بوابة 2: التوأم جاهز ومعزول فعلياً؟
        try:
            safe = self.twin.is_safe_to_test
        except SafetyViolationError:
            safe = False
        if not safe:
            logger.error("رفض %s: التوأم غير آمن", self.name)
            return TestResult(success=False,
                              proof="التوأم غير جاهز/معزول", **base)

        # بوابة 3: فحص أولي
        if not self.check_vulnerability():
            return TestResult(success=False,
                              proof="الهدف غير مصاب", **base)

        start = time.perf_counter()
        result = self._run_test()
        result.execution_time_ms = round((time.perf_counter() - start) * 1000, 2)
        result.module_name = self.name

        # التأكيد المزدوج — لا ثغرة بدون إعادة تحقق
        if result.success:
            result.verified = self.verify()
            if not result.verified:
                result.success = False
                result.proof += " | [✗] فشل التأكيد — إيجابي كاذب محتمل"

        return result

    def verify(self) -> bool:
        """الافتراضي: إعادة الفحص الأولي مرة إضافية."""
        return self.check_vulnerability()

    def abort(self) -> None:
        self._aborted = True
