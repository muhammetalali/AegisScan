"""نموذج الإصلاح — Remediation Model.

دورة الحياة: توليد → اختبار في التوأم → موافقة/تطبيق.
(الطبقة 4 — تُستخدم عند بناء AADA لاحقاً)
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class RemediationStatus(str, Enum):
    GENERATED = "generated"
    TESTING = "testing"
    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    APPLIED = "applied"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class RemediationMethod(str, Enum):
    PATTERN_BASED = "pattern_based"
    LLM_GENERATED = "llm_generated"
    MANUAL = "manual"


class RemediationTestResult(BaseModel):
    test_type: str
    passed: bool
    details: Optional[str] = None
    duration_ms: Optional[float] = None


class Remediation(BaseModel):
    id: str = Field(default_factory=lambda: f"rem_{uuid.uuid4().hex[:12]}")
    finding_id: str
    status: RemediationStatus = RemediationStatus.GENERATED
    method: RemediationMethod = RemediationMethod.PATTERN_BASED
    generated_patch: str = Field(..., min_length=1)
    old_code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    test_results: List[RemediationTestResult] = Field(default_factory=list)
    pull_request_url: Optional[str] = None
    applied_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def all_tests_passed(self) -> bool:
        return bool(self.test_results) and all(t.passed for t in self.test_results)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
