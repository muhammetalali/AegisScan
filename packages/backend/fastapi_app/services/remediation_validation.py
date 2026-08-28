from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    checks: tuple[dict[str, Any], ...]
    blocked: bool = False


class RemediationValidationSuite:
    """Approval-gated validation contract for changes before production rollout."""

    def validate(self, candidate: dict[str, Any], checks: dict[str, Callable[[dict[str, Any]], bool]]) -> dict[str, Any]:
        if not candidate.get("approval_id"):
            return ValidationResult(False, (), True).__dict__
        results = []
        for name, check in checks.items():
            try:
                passed = bool(check(candidate))
                results.append({"check": name, "passed": passed})
            except Exception as exc:  # validation must fail closed
                results.append({"check": name, "passed": False, "error": type(exc).__name__})
        return ValidationResult(all(x["passed"] for x in results), tuple(results), False).__dict__
