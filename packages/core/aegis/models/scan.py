"""نموذج جلسة الفحص — Scan Model."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from aegis.core.scan_state_machine import ScanPhase, ScanStateMachine


def _new_id() -> str:
    return f"scan_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
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
    started_at: datetime | None = None
    finished_at: datetime | None = None
    evidence_count: int = 0
    finding_count: int = 0
    phase: ScanPhase = ScanPhase.IDLE
    phase_history: list[dict[str, Any]] = Field(default_factory=list)

    def start(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = _utcnow()
        machine = ScanStateMachine(phase=self.phase, history=[])
        machine.transition(ScanPhase.PREPARING, reason='scan started')
        self.phase = machine.phase
        self.phase_history.extend(item.model_dump(mode='json') for item in machine.history)

    def transition(self, phase: ScanPhase, reason: str = '') -> None:
        machine = ScanStateMachine(phase=self.phase)
        machine.history = [
            {
                'from_phase': item['from_phase'],
                'to_phase': item['to_phase'],
                'at': item.get('at', _utcnow()),
                'reason': item.get('reason', ''),
            }
            for item in self.phase_history
        ]
        machine.transition(phase, reason=reason)
        self.phase = machine.phase
        self.phase_history.append(machine.history[-1].model_dump(mode='json'))
        if phase == ScanPhase.PAUSED:
            self.status = ScanStatus.PAUSED
        elif phase in {ScanPhase.FAILED, ScanPhase.CANCELLED}:
            self.status = ScanStatus.FAILED if phase == ScanPhase.FAILED else ScanStatus.CANCELLED

    def pause(self, reason: str = 'paused by operator') -> None:
        machine = ScanStateMachine(phase=self.phase)
        machine.pause(reason)
        self.phase = machine.phase
        self.status = ScanStatus.PAUSED
        self.phase_history.append(machine.history[-1].model_dump(mode='json'))

    def resume(self, reason: str = 'resumed by operator') -> None:
        machine = ScanStateMachine(phase=self.phase, resume_phase=self._resume_phase())
        machine.resume(reason)
        self.phase = machine.phase
        self.status = ScanStatus.RUNNING
        self.phase_history.append(machine.history[-1].model_dump(mode='json'))

    def _resume_phase(self) -> ScanPhase | None:
        for item in reversed(self.phase_history):
            if item.get('to_phase') == ScanPhase.PAUSED.value:
                return ScanPhase(item['from_phase'])
        return None

    def complete(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.finished_at = _utcnow()
        if self.phase not in {ScanPhase.DONE, ScanPhase.IDLE}:
            self.phase_history.append({
                'from_phase': self.phase.value,
                'to_phase': ScanPhase.DONE.value,
                'at': _utcnow().isoformat(),
                'reason': 'scan completed',
            })
            self.phase = ScanPhase.DONE

    def fail(self) -> None:
        self.status = ScanStatus.FAILED
        self.finished_at = _utcnow()
        if self.phase not in {ScanPhase.FAILED, ScanPhase.DONE}:
            machine = ScanStateMachine(phase=self.phase)
            if ScanPhase.FAILED in machine._FLOW.get(self.phase, set()):
                machine.transition(ScanPhase.FAILED, reason='scan failed')
                self.phase = machine.phase
                self.phase_history.append(machine.history[-1].model_dump(mode='json'))

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
