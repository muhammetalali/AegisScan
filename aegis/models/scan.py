"""نموذج جلسة الفحص — Scan Model."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _new_id() -> str:
    return f"scan_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    ANALYZING = "analyzing"
    CORRELATING = "correlating"
    TESTING = "testing"
    REMEDIATING = "remediating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    FULL = "full"
    CODE_ONLY = "code_only"
    URL_ONLY = "url_only"


class Scan(BaseModel):
    """جلسة فحص واحدة — كل الأدلة والثغرات ترتبط بمعرفها."""

    id: str = Field(default_factory=_new_id)
    project_id: str = "default"
    scan_type: ScanType = ScanType.FULL
    status: ScanStatus = ScanStatus.PENDING
    target: str
    config: dict[str, Any] = Field(default_factory=dict)
    triggered_by: str = "cli"
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    evidence_count: int = 0
    finding_count: int = 0

    def start(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = _utcnow()

    def complete(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.finished_at = _utcnow()

    def fail(self) -> None:
        self.status = ScanStatus.FAILED
        self.finished_at = _utcnow()

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
