from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from enterprise.models import DecisionAction, DecisionActionEvent

ACTIVE_STATES = ("pending", "approved", "assigned", "in_progress", "awaiting_revalidation")


def evaluate_sla_actions(now: datetime | None = None) -> list[dict[str, Any]]:
    now=now or timezone.now(); changed=[]
    action_ids=list(DecisionAction.objects.filter(state__in=ACTIVE_STATES).values_list('action_id',flat=True))
    for action_id in action_ids:
        with transaction.atomic():
            action=DecisionAction.objects.select_for_update().filter(pk=action_id,state__in=ACTIVE_STATES).first()
            if action is None: continue
            due_at=action.created_at+timedelta(hours=action.sla_hours)
            remaining_seconds=int((due_at-now).total_seconds()); ratio=remaining_seconds/max(1,action.sla_hours*3600)
            desired="breached" if remaining_seconds<=0 else "at_risk" if ratio<=0.2 else "on_track"
            level=action.escalation_level
            if desired=="at_risk" and level<1: level=1
            if desired=="breached" and level<2: level=2
            if desired==action.sla_status and level==action.escalation_level: continue
            action.sla_status=desired; action.escalation_level=level; action.updated_at=now; action.version+=1
            action.save(update_fields=['sla_status','escalation_level','updated_at','version'])
            event_type="action.sla_breached" if desired=="breached" else "action.sla_at_risk" if desired=="at_risk" else "action.sla_recovered"
            DecisionActionEvent.objects.create(action=action,event_type=event_type,actor="system",note=f"SLA status={desired}; escalation_level={level}",created_at=now)
            changed.append({"actionId":action.action_id,"owner":action.owner,"state":action.state,"priority":action.priority,
                            "slaStatus":desired,"escalationLevel":level,"remainingSeconds":remaining_seconds,"dueAt":due_at.isoformat()})
    return changed
