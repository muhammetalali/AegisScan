from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from psycopg2.pool import ThreadedConnectionPool

from ..core.config import settings

STATES = ["pending", "approved", "assigned", "in_progress", "awaiting_revalidation", "verified", "rejected", "deferred"]
TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "deferred"},
    "approved": {"assigned", "deferred"},
    "assigned": {"in_progress", "deferred"},
    "in_progress": {"awaiting_revalidation", "deferred"},
    "awaiting_revalidation": {"verified", "in_progress", "deferred"},
    "verified": set(), "rejected": set(), "deferred": {"pending", "approved"},
}

_pool: ThreadedConnectionPool | None = None
_schema_ready = False


def _now() -> datetime: return datetime.now(timezone.utc)


def _pool_instance() -> ThreadedConnectionPool:
    global _pool
    if _pool is None: _pool = ThreadedConnectionPool(1, 10, settings.DATABASE_URL)
    return _pool


def initialize_action_store() -> None: _ensure_schema()


def _ensure_schema() -> None:
    global _schema_ready
    # Schema ownership belongs to Django migration 0007. Runtime workers must
    # never perform DDL; compose waits for the migrated Django service.
    _schema_ready = True


def _event_row(row: tuple[Any, ...]) -> dict[str, Any]: return {"type": row[0], "at": row[1].isoformat(), "actor": row[2], "note": row[3]}


def _hydrate(cur, row: tuple[Any, ...]) -> dict[str, Any]:
    action_id, decision_id, node_id, title, owner, requested_by, sla_hours, state, risk_before, confidence_before, priority, recommended_action, remediation_plan, created_at, updated_at, version, sla_status, escalation_level = row
    cur.execute("SELECT event_type, created_at, actor, note FROM security_decision_action_events WHERE action_id = %s ORDER BY event_id ASC", (action_id,))
    events = [_event_row(event) for event in cur.fetchall()]
    due_at = created_at + timedelta(hours=sla_hours)
    return {"actionId": action_id, "decisionId": decision_id, "nodeId": node_id, "title": title, "owner": owner, "requestedBy": requested_by,
            "slaHours": sla_hours, "state": state, "riskBefore": risk_before, "confidenceBefore": confidence_before, "priority": priority,
            "recommendedAction": recommended_action, "remediationPlan": remediation_plan if isinstance(remediation_plan, list) else json.loads(remediation_plan or "[]"),
            "createdAt": created_at.isoformat(), "updatedAt": updated_at.isoformat(), "dueAt": due_at.isoformat(), "version": version,
            "slaStatus": sla_status, "escalationLevel": escalation_level, "events": events}


def create_action(decision: dict[str, Any], owner: str, sla_hours: int, requested_by: str) -> dict[str, Any]:
    _ensure_schema(); action_id = f"act-{uuid4().hex[:12]}"; now = _now(); pool = _pool_instance(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO security_decision_actions (action_id,decision_id,node_id,title,owner,requested_by,sla_hours,state,risk_before,confidence_before,priority,recommended_action,remediation_plan,created_at,updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (action_id, str(decision.get("decisionId") or ""), str(decision.get("nodeId") or "unknown"), f"Remediate: {decision.get('label','Security finding')}", owner, requested_by, max(1, sla_hours), "pending", int(decision.get("risk",0) or 0), int(decision.get("confidence",0) or 0), int(decision.get("priority",0) or 0), decision.get("recommendedAction","Apply remediation and re-validate."), json.dumps(decision.get("revalidationPlan",[])), now, now))
            cur.execute("INSERT INTO security_decision_action_events (action_id,event_type,actor,created_at) VALUES (%s,%s,%s,%s)", (action_id,"action.created",requested_by,now))
            cur.execute("SELECT * FROM security_decision_actions WHERE action_id=%s", (action_id,)); item=_hydrate(cur,cur.fetchone()); conn.commit(); return item
    finally: pool.putconn(conn)


def transition(action_id: str, state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    _ensure_schema()
    if state not in STATES: raise ValueError(f"Invalid state: {state}")
    pool = _pool_instance(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT state, version FROM security_decision_actions WHERE action_id=%s AND requested_by=%s FOR UPDATE", (action_id, actor)); row=cur.fetchone()
            if row is None: raise KeyError(action_id)
            current, version=row
            if state not in TRANSITIONS.get(current,set()): raise ValueError(f"Invalid transition: {current} -> {state}")
            now=_now(); cur.execute("UPDATE security_decision_actions SET state=%s,updated_at=%s,version=version+1 WHERE action_id=%s AND requested_by=%s AND version=%s",(state,now,action_id,actor,version))
            if cur.rowcount!=1: raise RuntimeError("Concurrent action update detected")
            cur.execute("INSERT INTO security_decision_action_events(action_id,event_type,actor,note,created_at) VALUES(%s,%s,%s,%s,%s)",(action_id,f"action.{state}",actor,note,now))
            cur.execute("SELECT * FROM security_decision_actions WHERE action_id=%s AND requested_by=%s",(action_id,actor)); item=_hydrate(cur,cur.fetchone()); conn.commit(); return item
    finally: pool.putconn(conn)


def list_actions(requested_by: str) -> list[dict[str, Any]]:
    _ensure_schema(); pool=_pool_instance(); conn=pool.getconn()
    try:
        with conn.cursor() as cur: cur.execute("SELECT * FROM security_decision_actions WHERE requested_by=%s ORDER BY updated_at DESC",(requested_by,)); return [_hydrate(cur,row) for row in cur.fetchall()]
    finally: pool.putconn(conn)


def get_action(action_id: str, requested_by: str) -> dict[str, Any] | None:
    _ensure_schema(); pool=_pool_instance(); conn=pool.getconn()
    try:
        with conn.cursor() as cur: cur.execute("SELECT * FROM security_decision_actions WHERE action_id=%s AND requested_by=%s",(action_id,requested_by)); row=cur.fetchone(); return _hydrate(cur,row) if row else None
    finally: pool.putconn(conn)
