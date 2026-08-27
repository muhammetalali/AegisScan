from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .decision_action_orchestration import _ensure_schema, _pool_instance

ACTIVE_STATES = ("pending", "approved", "assigned", "in_progress", "awaiting_revalidation")


def evaluate_sla_actions(now: datetime | None = None) -> list[dict[str, Any]]:
    _ensure_schema()
    now = now or datetime.now(timezone.utc)
    pool = _pool_instance()
    conn = pool.getconn()
    changed: list[dict[str, Any]] = []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id, owner, state, created_at, updated_at, sla_hours, priority, sla_status, escalation_level, version FROM security_decision_actions WHERE state = ANY(%s)", (list(ACTIVE_STATES),))
            rows = cur.fetchall()
            for row in rows:
                action_id, owner, state, created_at, updated_at, sla_hours, priority, sla_status, escalation_level, version = row
                due_at = created_at + __import__("datetime").timedelta(hours=sla_hours)
                remaining_seconds = int((due_at - now).total_seconds())
                ratio = remaining_seconds / max(1, sla_hours * 3600)
                desired = "breached" if remaining_seconds <= 0 else "at_risk" if ratio <= 0.2 else "on_track"
                level = int(escalation_level or 0)
                if desired == "at_risk" and level < 1:
                    level = 1
                if desired == "breached" and level < 2:
                    level = 2
                if desired != sla_status or level != int(escalation_level or 0):
                    cur.execute("UPDATE security_decision_actions SET sla_status=%s, escalation_level=%s, updated_at=%s, version=version+1 WHERE action_id=%s AND version=%s", (desired, level, now, action_id, version))
                    if cur.rowcount != 1:
                        continue
                    event_type = "action.sla_breached" if desired == "breached" else "action.sla_at_risk" if desired == "at_risk" else "action.sla_recovered"
                    cur.execute("INSERT INTO security_decision_action_events (action_id,event_type,actor,note,created_at) VALUES (%s,%s,%s,%s,%s)", (action_id, event_type, "system", f"SLA status={desired}; escalation_level={level}", now))
                    changed.append({"actionId": action_id, "owner": owner, "state": state, "priority": int(priority or 0), "slaStatus": desired, "escalationLevel": level, "remainingSeconds": remaining_seconds, "dueAt": due_at.isoformat()})
            conn.commit()
            return changed
    finally:
        pool.putconn(conn)
