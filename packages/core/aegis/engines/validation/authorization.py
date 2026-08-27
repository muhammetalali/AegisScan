"""Authorization Gate — بوابة التفويض.

تحمّل كل إجراء قبل تنفيذه: هل هو مصرّح به؟ هل في النطاق المسموح؟
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("aegis.validation.authorization")


class ActionLevel(str, Enum):
    """مستوى الإجراء."""
    READ = "read"           # قراءة فقط
    ANALYZE = "analyze"     # تحليل
    WRITE = "write"         # كتابة/تعديل
    EXECUTE = "execute"     # تنفيذ أوامر
    DESTRUCTIVE = "destructive"  # إجراءات تدميرية


@dataclass
class AuthorizationPolicy:
    """سياسة التفويض."""
    allowed_levels: Set[ActionLevel] = field(
        default_factory=lambda: {ActionLevel.READ, ActionLevel.ANALYZE}
    )
    allowed_targets: Set[str] = field(default_factory=set)
    max_concurrent_actions: int = 10
    require_approval_above: ActionLevel = ActionLevel.WRITE
    time_window_seconds: int = 3600  # ساعة واحدة كحد أقصى


@dataclass
class AuthorizationRequest:
    """طلب تفويض."""
    action_id: str
    action_type: str
    level: ActionLevel
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    requested_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if self.requested_at is None:
            self.requested_at = datetime.now(timezone.utc)


@dataclass
class AuthorizationResult:
    """نتيجة التفويض."""
    authorized: bool
    action_id: str
    reason: str
    requires_approval: bool = False
    expires_at: Optional[datetime] = None


class AuthorizationGate:
    """بوابة التفويض — تتحقق من صلاحية كل إجراء قبل التنفيذ."""

    name = "AuthorizationGate"

    def __init__(self, policy: Optional[AuthorizationPolicy] = None) -> None:
        self.policy = policy or AuthorizationPolicy()
        self._active_actions: Dict[str, AuthorizationRequest] = {}
        self._approved_actions: Set[str] = set()
        self._denied_actions: Set[str] = set()

    def check(self, request: AuthorizationRequest) -> AuthorizationResult:
        """التحقق من تفويض إجراء."""
        # 1. هل المستوى مسموح؟
        if request.level not in self.policy.allowed_levels:
            reason = f"المستوى '{request.level.value}' غير مسموح — المستويات المسموحة: {[l.value for l in self.policy.allowed_levels]}"
            self._denied_actions.add(request.action_id)
            logger.warning("رفض %s: %s", request.action_id, reason)
            return AuthorizationResult(
                authorized=False,
                action_id=request.action_id,
                reason=reason,
            )

        # 2. هل الهدف مسموح؟
        if (
            self.policy.allowed_targets
            and request.target not in self.policy.allowed_targets
        ):
            reason = f"الهدف '{request.target}' غير مصرّح به"
            self._denied_actions.add(request.action_id)
            logger.warning("رفض %s: %s", request.action_id, reason)
            return AuthorizationResult(
                authorized=False,
                action_id=request.action_id,
                reason=reason,
            )

        # 3. هل يوجد عدد كافٍ من الإجراءات النشطة؟
        if len(self._active_actions) >= self.policy.max_concurrent_actions:
            reason = "تم تجاوز الحد الأقصى للإجراءات المتزامنة"
            self._denied_actions.add(request.action_id)
            return AuthorizationResult(
                authorized=False,
                action_id=request.action_id,
                reason=reason,
            )

        # 4. هل يحتاج موافقة؟
        needs_approval = self._needs_approval(request.level)

        if needs_approval and request.action_id not in self._approved_actions:
            self._active_actions[request.action_id] = request
            return AuthorizationResult(
                authorized=False,
                action_id=request.action_id,
                reason="يحتاج موافقة يدوية",
                requires_approval=True,
            )

        # ✅ م مصرّح
        self._active_actions[request.action_id] = request
        return AuthorizationResult(
            authorized=True,
            action_id=request.action_id,
            reason="مصرّح",
        )

    def approve(self, action_id: str) -> bool:
        """الموافقة على إجراء."""
        if action_id in self._active_actions:
            self._approved_actions.add(action_id)
            logger.info("تمت الموافقة على %s", action_id)
            return True
        return False

    def complete(self, action_id: str) -> None:
        """تحديد إجراء كمكتمل."""
        self._active_actions.pop(action_id, None)
        self._approved_actions.discard(action_id)

    def deny(self, action_id: str, reason: str = "رفض يدوي") -> None:
        """رفض إجراء."""
        self._active_actions.pop(action_id, None)
        self._denied_actions.add(action_id)
        logger.info("رفض %s: %s", action_id, reason)

    def status(self) -> Dict[str, Any]:
        """حالة البوابة."""
        return {
            "active_actions": len(self._active_actions),
            "approved": len(self._approved_actions),
            "denied": len(self._denied_actions),
            "policy": {
                "allowed_levels": [l.value for l in self.policy.allowed_levels],
                "max_concurrent": self.policy.max_concurrent_actions,
            },
        }

    def _needs_approval(self, level: ActionLevel) -> bool:
        """تحديد ما إذا كان المستوى يحتاج موافقة."""
        levels_order = list(ActionLevel)
        current_idx = levels_order.index(level)
        threshold_idx = levels_order.index(self.policy.require_approval_above)
        return current_idx >= threshold_idx
