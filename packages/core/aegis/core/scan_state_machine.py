"""آلة حالات فحص قابلة للإيقاف والاستئناف وإعادة المرحلة."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel, Field


class ScanPhase(str, Enum):
    IDLE = 'idle'
    PREPARING = 'preparing'
    SCANNING = 'scanning'
    CORRELATING = 'correlating'
    TESTING = 'testing'
    REMEDIATING = 'remediating'
    REPORTING = 'reporting'
    DONE = 'done'
    PAUSED = 'paused'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class PhaseTransition(BaseModel):
    from_phase: ScanPhase
    to_phase: ScanPhase
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ''


class ScanStateMachine(BaseModel):
    phase: ScanPhase = ScanPhase.IDLE
    resume_phase: ScanPhase | None = None
    history: list[PhaseTransition] = Field(default_factory=list)

    _FLOW: ClassVar[dict[ScanPhase, set[ScanPhase]]] = {
        ScanPhase.IDLE: {ScanPhase.PREPARING},
        ScanPhase.PREPARING: {ScanPhase.SCANNING, ScanPhase.FAILED, ScanPhase.CANCELLED},
        ScanPhase.SCANNING: {ScanPhase.CORRELATING, ScanPhase.FAILED, ScanPhase.CANCELLED},
        ScanPhase.CORRELATING: {ScanPhase.TESTING, ScanPhase.FAILED, ScanPhase.CANCELLED},
        ScanPhase.TESTING: {ScanPhase.REMEDIATING, ScanPhase.REPORTING, ScanPhase.FAILED, ScanPhase.CANCELLED},
        ScanPhase.REMEDIATING: {ScanPhase.REPORTING, ScanPhase.FAILED, ScanPhase.CANCELLED},
        ScanPhase.REPORTING: {ScanPhase.DONE, ScanPhase.FAILED},
        ScanPhase.DONE: set(),
        ScanPhase.PAUSED: set(),
        ScanPhase.FAILED: set(),
        ScanPhase.CANCELLED: set(),
    }

    def transition(self, target: ScanPhase, reason: str = '') -> None:
        if target == self.phase:
            return
        if target not in self._FLOW.get(self.phase, set()):
            raise ValueError(f'Invalid scan transition: {self.phase.value} -> {target.value}')
        self.history.append(PhaseTransition(from_phase=self.phase, to_phase=target, reason=reason))
        self.phase = target

    def pause(self, reason: str = 'paused by operator') -> None:
        if self.phase not in {
            ScanPhase.PREPARING, ScanPhase.SCANNING, ScanPhase.CORRELATING,
            ScanPhase.TESTING, ScanPhase.REMEDIATING, ScanPhase.REPORTING,
        }:
            raise ValueError(f'Cannot pause scan in phase: {self.phase.value}')
        self.resume_phase = self.phase
        self.history.append(PhaseTransition(from_phase=self.phase, to_phase=ScanPhase.PAUSED, reason=reason))
        self.phase = ScanPhase.PAUSED

    def resume(self, reason: str = 'resumed by operator') -> None:
        if self.phase != ScanPhase.PAUSED or self.resume_phase is None:
            raise ValueError('Scan is not paused')
        previous = self.phase
        target = self.resume_phase
        self.history.append(PhaseTransition(from_phase=previous, to_phase=target, reason=reason))
        self.phase = target
        self.resume_phase = None

    def restart_from(self, phase: ScanPhase, reason: str = 'stage restarted') -> None:
        if phase in {ScanPhase.IDLE, ScanPhase.PAUSED, ScanPhase.DONE, ScanPhase.FAILED, ScanPhase.CANCELLED}:
            raise ValueError('A restart must target an executable stage')
        if self.phase not in {ScanPhase.DONE, ScanPhase.FAILED, ScanPhase.CANCELLED}:
            raise ValueError('Restart is allowed only after a terminal scan state')
        self.history.append(PhaseTransition(from_phase=self.phase, to_phase=phase, reason=reason))
        self.phase = phase
        self.resume_phase = None
