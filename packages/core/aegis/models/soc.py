"""نموذج قصة الهجوم — AttackStory Model.

يُستخدم من SOCEngine لتحويل الأدلة والثغرات إلى خط زمني + أنماط + سرد مقروء.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from pydantic import BaseModel, Field


def _new_id() -> str:
    return f"story_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AttackStory(BaseModel):
    """قصة هجوم موحدة: خط زمني + أنماط + أفعال مقترحة."""

    id: str = Field(default_factory=_new_id)
    scan_id: str
    title: str
    summary: str
    severity: str = "info"
    event_count: int = 0
    detected_patterns: List[str] = Field(default_factory=list)
    pattern_details: List[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=_utcnow)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def __repr__(self) -> str:
        return (
            f"AttackStory(id={self.id!r}, scan={self.scan_id!r}, "
            f"severity={self.severity!r})"
        )
