"""AePEX — منسق الطبقة 3: يدير الاختبار داخل التوأم فقط.

ضوابط صارمة:
1. قائمة سماح للأهداف (allowed_target_prefixes) — استهداف أي شيء آخر مرفوض.
2. كل عملية تُسجَّل في AuditLogger إلزامياً.
3. لا وحدات مسجلة افتراضياً — تُضاف فوق أدوات اختبار معتمدة لاحقاً.
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit
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

    @staticmethod
    def _parse_target(value: str) -> tuple[str, str, int | None, str] | None:
        """Return (scheme, host, port, path) without trusting raw string prefixes."""
        raw = (value or "").strip()
        if not raw:
            return None
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname
        if not host:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        return (
            parsed.scheme.lower(),
            host.rstrip(".").lower(),
            port,
            parsed.path or "/",
        )

    @staticmethod
    def _ip_or_host(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.rstrip(".").lower()

    def _target_allowed(self, target: str) -> bool:
        """Allow only the exact configured host/origin and its explicit path descendants.

        Legacy dotted prefixes such as ``10.0.0.`` are intentionally rejected because
        raw ``startswith`` authorization can be bypassed with attacker-controlled hosts.
        Network ranges must be expressed by the higher-level scanner allowlist as CIDR.
        """
        candidate = self._parse_target(target)
        if candidate is None:
            return False
        scheme, host, port, path = candidate
        host = self._ip_or_host(host)

        for configured in self.allowed_target_prefixes:
            allowed = self._parse_target(str(configured))
            if allowed is None:
                continue
            allowed_scheme, allowed_host, allowed_port, allowed_path = allowed
            allowed_host = self._ip_or_host(allowed_host)

            if host != allowed_host or port != allowed_port:
                continue
            if allowed_scheme and scheme and scheme != allowed_scheme:
                continue

            normalized_allowed_path = allowed_path.rstrip("/") or "/"
            normalized_candidate_path = path or "/"
            if normalized_allowed_path == "/":
                return True
            if normalized_candidate_path == normalized_allowed_path:
                return True
            if normalized_candidate_path.startswith(normalized_allowed_path + "/"):
                return True

        return False

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