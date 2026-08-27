"""نموذج الثغرة الموحدة — Unified Finding Model.

لا يُنشأ Finding إلا بواسطة Correlation Engine بعد حساب الثقة رياضياً.
قاعدة المادة 1: دليلان مستقلان على الأقل إلزامياً.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator

from aegis.models.evidence import EvidenceCategory
from aegis.models.provenance import DecisionStep


def _new_id() -> str:
    return f"f_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    DETECTED = "detected"
    CORRELATED = "correlated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    PATCHED = "patched"
    NEEDS_REVIEW = "needs_review"


class Finding(BaseModel):
    """ثغرة موحدة مدعومة بأدلة مستقلة ودرجة ثقة محسوبة."""

    id: str = Field(default_factory=_new_id)
    scan_id: str
    title: str = Field(..., min_length=8, max_length=256)
    severity: Severity = Severity.MEDIUM
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.DETECTED
    category: EvidenceCategory = EvidenceCategory.UNKNOWN
    description: str = Field(..., min_length=15)
    root_cause: str | None = None
    attack_path: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    remediation_suggestion: str | None = None
    exploit_proof: str | None = None
    decision_trail: list[DecisionStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def _require_two_evidences(cls, v: list[str]) -> list[str]:
        """المادة 1 (الدليل المطلق): لا ثغرة بأقل من دليلين مستقلين."""
        if len(v) < 2:
            raise ValueError(
                f"الثغرة يجب أن ترتبط بدليلين مستقلين على الأقل "
                f"(الحالي: {len(v)}) — التوجيهات الصارمة، المادة 1"
            )
        return v

    @computed_field
    @property
    def evidence_count(self) -> int:
        return len(self.evidence_ids)

    @computed_field
    @property
    def is_confirmed(self) -> bool:
        return self.status == FindingStatus.CONFIRMED

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, title={self.title!r}, "
            f"sev={self.severity.value!r}, conf={self.confidence_score:.2f})"
        )
