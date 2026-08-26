"""Execution Planner — مخطط التنفيذ.

يحوّل قائمة الإجراءات المطلوبة إلى خطة تنفيذ مرتّبة وآمنة.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.engines.validation.authorization import (
    AuthorizationGate,
    AuthorizationRequest,
    ActionLevel,
)

logger = logging.getLogger("aegis.validation.planner")


class PlanStatus(str, Enum):
    """حالة الخطة."""
    DRAFT = "draft"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PlannedAction:
    """إجراء مخطط."""
    action_id: str
    action_type: str
    level: ActionLevel
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    priority: int = 0  # 0 = عادي، أعلى = أهم


@dataclass
class ExecutionPlan:
    """خطة تنفيذ."""
    plan_id: str
    actions: List[PlannedAction]
    status: PlanStatus = PlanStatus.DRAFT
    created_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionPlanner:
    """مخطط التنفيذ — يرتب الإجراءات ويراعي الاعتماديات."""

    name = "ExecutionPlanner"

    def __init__(self, auth_gate: AuthorizationGate) -> None:
        self.auth_gate = auth_gate

    def create_plan(
        self,
        plan_id: str,
        actions: List[PlannedAction],
    ) -> ExecutionPlan:
        """إنشاء خطة تنفيذ."""
        # ترتيب حسب الأولوية ثم الاعتماديات
        sorted_actions = self._topological_sort(actions)

        plan = ExecutionPlan(
            plan_id=plan_id,
            actions=sorted_actions,
        )

        logger.info(
            "خطة %s: %d إجراءات",
            plan_id, len(sorted_actions),
        )
        return plan

    def authorize_plan(self, plan: ExecutionPlan) -> Dict[str, Any]:
        """التحقق من تفويض كل إجراء في الخطة."""
        results = {}
        all_authorized = True

        for action in plan.actions:
            request = AuthorizationRequest(
                action_id=action.action_id,
                action_type=action.action_type,
                level=action.level,
                target=action.target,
                parameters=action.parameters,
            )
            result = self.auth_gate.check(request)
            results[action.action_id] = {
                "authorized": result.authorized,
                "reason": result.reason,
                "requires_approval": result.requires_approval,
            }
            if not result.authorized:
                all_authorized = False

        if all_authorized:
            plan.status = PlanStatus.APPROVED

        return {
            "plan_id": plan.plan_id,
            "all_authorized": all_authorized,
            "results": results,
        }

    def get_ready_actions(self, plan: ExecutionPlan) -> List[PlannedAction]:
        """الحصول على الإجراءات الجاهزة للتنفيذ (التي تمت تلبيتها اعتمادياتها)."""
        completed_ids = plan.metadata.get("completed_actions", set())
        ready = []
        for action in plan.actions:
            if action.action_id in completed_ids:
                continue
            deps_met = all(
                dep in completed_ids for dep in action.depends_on
            )
            if deps_met:
                ready.append(action)
        return ready

    def mark_completed(self, plan: ExecutionPlan, action_id: str) -> None:
        """تحديد إجراء كمكتمل."""
        completed = plan.metadata.setdefault("completed_actions", set())
        completed.add(action_id)
        self.auth_gate.complete(action_id)

        # تحديث حالة الخطة
        if all(a.action_id in completed for a in plan.actions):
            plan.status = PlanStatus.COMPLETED

    @staticmethod
    def _topological_sort(actions: List[PlannedAction]) -> List[PlannedAction]:
        """ترتيبtéri المجرat حسب الاعتماديات."""
        action_map = {a.action_id: a for a in actions}
        visited: set = set()
        sorted_list: List[PlannedAction] = []

        def _visit(aid: str) -> None:
            if aid in visited:
                return
            visited.add(aid)
            action = action_map.get(aid)
            if action is None:
                return
            for dep in action.depends_on:
                _visit(dep)
            sorted_list.append(action)

        for action in actions:
            _visit(action.action_id)

        return sorted_list
