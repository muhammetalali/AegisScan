"""الطبقة 3 — الاختبار داخل التوأم الرقمي المعزول."""

from aegis.core.exceptions import SafetyViolationError
from aegis.engines.offensive.twin import (
    DigitalTwin,
    TwinConfig,
    TwinState,
    validate_compose_security,
)
from aegis.engines.offensive.base_module import BaseTestModule, TestResult
from aegis.engines.offensive.verifier import VerificationEngine
from aegis.engines.offensive.aepex import AePEX

__all__ = [
    "DigitalTwin", "TwinConfig", "TwinState",
    "SafetyViolationError", "validate_compose_security",
    "BaseTestModule", "TestResult",
    "VerificationEngine", "AePEX",
]
