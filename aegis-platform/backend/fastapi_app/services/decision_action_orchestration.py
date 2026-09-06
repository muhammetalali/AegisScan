from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

from django.db import transaction
from django.utils import timezone

from enterprise.models import DecisionAction, DecisionActionEvent

STATES = ["pending", "approved", "assigned", "in_progress", "awaiting_revalidation", "verified", "rejected", "deferred"]
TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "deferred"}, "approved": {"assigned", "deferred"},
    "assigned": {"in_progress", "deferred"}, "in_progress": {"awaiting_revalidation", "deferred"},
    "awaiting_revalidation": {"verified", "in_progress", "deferred"},
    "verified": set(), "rejected": set(), "deferred": {"pending", "approved"},
}
_schema_ready = False


def initialize_action_store() -> None:
    global _schema_ready
    _schema_ready = True


def _ensure_schema() -> None: initialize_action_store()


def _hydrate(action: DecisionAction) -> dict[str, Any]:
    events = [{"type": event.event_type, "at": event.created_at.isoformat(), "actor": event.actor, "note": event.note}
              for event in action.events.all()]
    return {
        "actionId":action.action_id,"decisionId":action.decision_id,"nodeId":action.node_id,"title":action.title,
        "owner":action.owner,"requestedBy":action.requested_by,"slaHours":action.sla_hours,"state":action.state,
        "riskBefore":action.risk_before,"confidenceBefore":action.confidence_before,"priority":action.priority,
        "recommendedAction":action.recommended_action,"remediationPlan":action.remediation_plan,
        "createdAt":action.created_at.isoformat(),"updatedAt":action.updated_at.isoformat(),
        "dueAt":(action.created_at+timedelta(hours=action.sla_hours)).isoformat(),"version":action.version,
        "slaStatus":action.sla_status,"escalationLevel":action.escalation_level,"events":events,
    }


def create_action(decision: dict[str, Any], owner: str, sla_hours: int, requested_by: str) -> dict[str, Any]:
    now=timezone.now()
    with transaction.atomic():
        action=DecisionAction.objects.create(
            action_id=f"act-{uuid4().hex[:12]}",decision_id=str(decision.get("decisionId") or ""),
            node_id=str(decision.get("nodeId") or "unknown"),title=f"Remediate: {decision.get('label','Security finding')}",
            owner=owner,requested_by=requested_by,sla_hours=max(1,sla_hours),state="pending",
            risk_before=int(decision.get("risk",0) or 0),confidence_before=int(decision.get("confidence",0) or 0),
            priority=int(decision.get("priority",0) or 0),recommended_action=decision.get("recommendedAction","Apply remediation and re-validate."),
            remediation_plan=decision.get("revalidationPlan",[]),created_at=now,updated_at=now,
        )
        DecisionActionEvent.objects.create(action=action,event_type="action.created",actor=requested_by,created_at=now)
    return _hydrate(DecisionAction.objects.prefetch_related('events').get(pk=action.pk))


def transition(action_id: str, state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    if state not in STATES: raise ValueError(f"Invalid state: {state}")
    with transaction.atomic():
        action=DecisionAction.objects.select_for_update().filter(pk=action_id,requested_by=actor).first()
        if action is None: raise KeyError(action_id)
        if state not in TRANSITIONS.get(action.state,set()): raise ValueError(f"Invalid transition: {action.state} -> {state}")
        now=timezone.now(); action.state=state; action.updated_at=now; action.version+=1
        action.save(update_fields=['state','updated_at','version'])
        DecisionActionEvent.objects.create(action=action,event_type=f"action.{state}",actor=actor,note=note,created_at=now)
    return _hydrate(DecisionAction.objects.prefetch_related('events').get(pk=action.pk,requested_by=actor))


def list_actions(requested_by: str) -> list[dict[str, Any]]:
    rows=DecisionAction.objects.filter(requested_by=requested_by).prefetch_related('events').order_by('-updated_at')
    return [_hydrate(row) for row in rows]


def get_action(action_id: str, requested_by: str) -> dict[str, Any] | None:
    action=DecisionAction.objects.filter(pk=action_id,requested_by=requested_by).prefetch_related('events').first()
    return _hydrate(action) if action else None
