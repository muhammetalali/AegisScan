"""نموذج الدليل الموحد — Unified Evidence Model.

كل مخرجات أي محرك (AST, BTE, ADI...) تُطبَّع إلى هذا الشكل قبل النشر.
التوجيه الصارم 1: الدليل أولاً — لا نتيجة بدون دليل.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


def _new_id() -> str:
    return f"ev_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceType(str, Enum):
    """نوع الدليل — يحدد مجموعته في معادلة الثقة."""

    AST = "ast"
    DATA_FLOW = "data_flow"
    TAINT = "taint"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    BEHAVIORAL = "behavioral"
    NETWORK = "network"
    DARKWEB = "darkweb"
    LOG = "log"
    EXPLOIT = "exploit"
    VERIFICATION = "verification"


class EvidenceCategory(str, Enum):
    """التصنيف الأمني للدليل."""

    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "logic"
    PRIVILEGE = "privilege"
    SECRETS = "secrets"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    INFORMATION_DISCLOSURE = "info_disclosure"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    """دليل واحد موحد ينتجه أي مكوّن داخل Aegis."""

    id: str = Field(default_factory=_new_id)
    scan_id: str
    source_tool: str
    evidence_type: EvidenceType
    category: EvidenceCategory = EvidenceCategory.UNKNOWN
    description: str = Field(..., min_length=5)
    location: Optional[str] = None
    raw_data: Optional[str] = Field(default=None, max_length=10_000)
    confidence_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    context: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)
    content_hash: Optional[str] = None

    @field_validator("source_tool")
    @classmethod
    def _clean_source(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("source_tool لا يمكن أن يكون فارغاً")
        return v

    def compute_hash(self) -> str:
        """بصمة الدليل لمنع التكرار (Deduplication) في محرك الربط."""
        fingerprint = (
            f"{self.source_tool}|{self.evidence_type.value}|{self.location}|{self.description}"
        )
        self.content_hash = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]
        return self.content_hash

    def model_post_init(self, __context: Any) -> None:
        if self.content_hash is None:
            self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def __repr__(self) -> str:
        return (
            f"Evidence(id={self.id!r}, tool={self.source_tool!r}, "
            f"type={self.evidence_type.value!r}, w={self.confidence_weight:.2f})"
        )
