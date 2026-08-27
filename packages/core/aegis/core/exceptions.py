"""استثناءات Aegis المخصصة — هرمية واضحة برموز فريدة."""

from __future__ import annotations

from typing import Any, Dict, Optional


class AegisError(Exception):
    """الاستثناء الأساسي لجميع أخطاء Aegis."""

    code: str = "AEGIS_ERROR"

    def __init__(
        self, message: str, details: Optional[Dict[str, Any]] = None
    ) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class EventBusError(AegisError):
    code = "EVENT_BUS_ERROR"


class PluginError(AegisError):
    code = "PLUGIN_ERROR"

    def __init__(self, plugin_name: str, message: str, **kwargs: Any) -> None:
        self.plugin_name = plugin_name
        super().__init__(
            f"[{plugin_name}] {message}", {"plugin": plugin_name, **kwargs}
        )


class DataManagerError(AegisError):
    code = "DATA_MANAGER_ERROR"


class ConfigError(AegisError):
    code = "CONFIG_ERROR"


class ValidationError(AegisError):
    code = "VALIDATION_ERROR"

    def __init__(
        self, model_name: str, message: str, field: Optional[str] = None
    ) -> None:
        self.model_name = model_name
        self.field = field
        super().__init__(
            f"[{model_name}] {message}", {"model": model_name, "field": field}
        )


class TwinError(AegisError):
    code = "TWIN_ERROR"


class TwinDriftError(TwinError):
    code = "TWIN_DRIFT"

    def __init__(self, drift: float, threshold: float) -> None:
        self.drift_percentage = drift
        self.threshold = threshold
        super().__init__(
            f"انحراف التوأم: {drift:.1f}% (الحد: {threshold}%)",
            {"drift": drift, "threshold": threshold},
        )


class ExploitError(AegisError):
    code = "EXPLOIT_ERROR"

    def __init__(self, module_name: str, message: str) -> None:
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}", {"module": module_name})


class SafetyViolationError(AegisError):
    """انتهاك السلامة: محاولة تنفيذ هجومي خارج البيئة المعزولة."""

    code = "SAFETY_VIOLATION"


class RemediationError(AegisError):
    code = "REMEDIATION_ERROR"


class OrchestratorError(AegisError):
    code = "ORCHESTRATOR_ERROR"


class OrchestratorBusyError(OrchestratorError):
    code = "ORCHESTRATOR_BUSY"


class AuditError(AegisError):
    code = "AUDIT_ERROR"


class ScanTargetError(AegisError):
    code = "SCAN_TARGET_INVALID"
