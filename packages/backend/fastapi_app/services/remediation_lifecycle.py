from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
from psycopg2.pool import ThreadedConnectionPool

from ..core.config import settings
from .decision_action_orchestration import get_action, transition
from .remediation_validation import RemediationValidationSuite
from .ticket_orchestration import TicketOrchestrator

_STATES = {"pending", "approved", "assigned", "in_progress", "awaiting_revalidation", "verified", "rejected", "deferred"}
_pool: ThreadedConnectionPool | None = None
_ready = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(1, 10, settings.DATABASE_URL)
    return _pool


def initialize_lifecycle_store() -> None:
    global _ready
    if _ready:
        return
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS remediation_integrations (
                action_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                external_id TEXT,
                external_url TEXT,
                integration_state TEXT NOT NULL,
                validation JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL
            )""")
            conn.commit(); _ready = True
    finally:
        pool.putconn(conn)


def _record(action_id: str, provider: str, external_id: str | None, external_url: str | None, state: str, validation: dict[str, Any] | None = None) -> None:
    initialize_lifecycle_store(); pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO remediation_integrations(action_id,provider,external_id,external_url,integration_state,validation,updated_at)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(action_id) DO UPDATE SET provider=EXCLUDED.provider, external_id=EXCLUDED.external_id,
                external_url=EXCLUDED.external_url, integration_state=EXCLUDED.integration_state,
                validation=EXCLUDED.validation, updated_at=EXCLUDED.updated_at""",
                (action_id, provider, external_id, external_url, state, json.dumps(validation or {}), _now()))
            conn.commit()
    finally:
        pool.putconn(conn)


def get_lifecycle(action_id: str) -> dict[str, Any] | None:
    initialize_lifecycle_store(); pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id,provider,external_id,external_url,integration_state,validation,updated_at FROM remediation_integrations WHERE action_id=%s", (action_id,))
            row = cur.fetchone()
            if not row:
                return None
            validation = row[5] if isinstance(row[5], dict) else json.loads(row[5] or "{}")
            return {"action_id": row[0], "provider": row[1], "external_id": row[2], "external_url": row[3], "integration_state": row[4], "validation": validation, "updated_at": row[6].isoformat()}
    finally:
        pool.putconn(conn)


async def create_action_and_ticket(*, decision: dict[str, Any], owner: str, sla_hours: int, actor: str, provider: str, evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from .decision_action_orchestration import create_action
    action = create_action(decision, owner, sla_hours, actor)
    ticket = await TicketOrchestrator().create_from_decision(provider=provider, decision={**decision, "final_score": decision.get("risk"), "severity": decision.get("severity")}, evidence=evidence or [])
    if ticket.get("status") != "created":
        _record(action["actionId"], provider, ticket.get("external_id"), ticket.get("url"), ticket.get("status", "not_configured"), {})
        return {"action": action, "ticket": ticket, "lifecycle": get_lifecycle(action["actionId"])}
    _record(action["actionId"], provider, ticket.get("external_id"), ticket.get("url"), "created", {})
    return {"action": action, "ticket": ticket, "lifecycle": get_lifecycle(action["actionId"])}


async def transition_with_ticket(action_id: str, target_state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    lifecycle = get_lifecycle(action_id)
    if lifecycle is None:
        raise KeyError(action_id)
    action = get_action(action_id)
    if action is None:
        raise KeyError(action_id)
    updated = transition(action_id, target_state, actor, note)
    ticket_sync = await _sync_external_ticket(lifecycle, target_state, note)
    _record(action_id, lifecycle["provider"], lifecycle.get("external_id"), lifecycle.get("external_url"), target_state if ticket_sync["status"] in {"synced", "noop"} else "sync_error", lifecycle.get("validation") or {})
    return {"action": updated, "ticket": ticket_sync, "lifecycle": get_lifecycle(action_id)}


async def validate_and_verify(action_id: str, actor: str, *, candidate: dict[str, Any], tools: list[str] | None = None, timeout: int = 180) -> dict[str, Any]:
    lifecycle = get_lifecycle(action_id)
    action = get_action(action_id)
    if lifecycle is None or action is None:
        raise KeyError(action_id)
    current = action["state"]
    if current not in {"in_progress", "awaiting_revalidation"}:
        raise ValueError(f"action must be in_progress or awaiting_revalidation, got {current}")
    if current == "in_progress":
        transition(action_id, "awaiting_revalidation", actor, "Automatic remediation revalidation started")
    result = await RemediationValidationSuite().validate_workspace(candidate, tools=tools, timeout=timeout)
    before = candidate.get("risk_before", action.get("riskBefore", 0))
    after = candidate.get("risk_after", before)
    result["risk_diff"] = RemediationValidationSuite.compare_scores(float(before), float(after))
    lifecycle = get_lifecycle(action_id) or lifecycle
    if result.get("passed") and not result["risk_diff"].get("regressed"):
        updated = transition(action_id, "verified", actor, "Automated remediation validation passed and risk did not regress")
        target_state = "verified"
    else:
        updated = transition(action_id, "in_progress", actor, "Validation failed or risk regressed; remediation remains open")
        target_state = "in_progress"
    sync = await _sync_external_ticket(lifecycle, target_state, result.get("summary") and json.dumps(result.get("summary")))
    _record(action_id, lifecycle["provider"], lifecycle.get("external_id"), lifecycle.get("external_url"), target_state, result)
    return {"action": updated, "ticket": sync, "validation": result, "lifecycle": get_lifecycle(action_id)}


async def _sync_external_ticket(lifecycle: dict[str, Any], state: str, note: str | None) -> dict[str, Any]:
    provider = lifecycle["provider"]
    external_id = lifecycle.get("external_id")
    if not external_id:
        return {"provider": provider, "status": "noop", "reason": "no external ticket id"}
    try:
        if provider == "jira":
            base = os.getenv("JIRA_BASE_URL", "").rstrip("/"); token = os.getenv("JIRA_API_TOKEN"); email = os.getenv("JIRA_USER_EMAIL")
            if not all((base, token, email)):
                return {"provider": provider, "status": "not_configured"}
            async with httpx.AsyncClient(timeout=15, auth=(email, token), headers={"Accept": "application/json", "Content-Type": "application/json"}) as client:
                transitions = await client.get(f"{base}/rest/api/3/issue/{external_id}/transitions")
                transitions.raise_for_status(); data = transitions.json()
                names = {"approved": os.getenv("JIRA_STATUS_APPROVED", "In Progress"), "assigned": os.getenv("JIRA_STATUS_ASSIGNED", "In Progress"), "in_progress": os.getenv("JIRA_STATUS_IN_PROGRESS", "In Progress"), "awaiting_revalidation": os.getenv("JIRA_STATUS_REVALIDATION", "In Review"), "verified": os.getenv("JIRA_STATUS_VERIFIED", "Done"), "rejected": os.getenv("JIRA_STATUS_REJECTED", "Won't Do"), "deferred": os.getenv("JIRA_STATUS_DEFERRED", "To Do"), "pending": os.getenv("JIRA_STATUS_PENDING", "To Do")}
                wanted = names.get(state, "In Progress")
                transition_id = next((str(item.get("id")) for item in transitions.json().get("transitions", []) if str(item.get("to", {}).get("name", "")).lower() == wanted.lower()), None)
                if not transition_id:
                    return {"provider": provider, "status": "sync_error", "reason": f"No Jira transition to status '{wanted}'"}
                response = await client.post(f"{base}/rest/api/3/issue/{external_id}/transitions", json={"transition": {"id": transition_id}})
                response.raise_for_status()
                return {"provider": provider, "status": "synced", "external_id": external_id, "target_state": state}
        if provider == "servicenow":
            base = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/"); token = os.getenv("SERVICENOW_API_TOKEN")
            if not base or not token:
                return {"provider": provider, "status": "not_configured"}
            states = {"pending": "1", "approved": "2", "assigned": "2", "in_progress": "2", "awaiting_revalidation": "2", "verified": "7", "rejected": "8", "deferred": "3"}
            table = os.getenv("SERVICENOW_TABLE", "incident")
            async with httpx.AsyncClient(timeout=15, headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}) as client:
                response = await client.patch(f"{base}/api/now/table/{table}/{external_id}", json={"state": states.get(state, "2"), "comments": note or f"AegisScan lifecycle state: {state}"})
                response.raise_for_status()
                return {"provider": provider, "status": "synced", "external_id": external_id, "target_state": state}
    except Exception as exc:
        return {"provider": provider, "status": "sync_error", "reason": type(exc).__name__}
    return {"provider": provider, "status": "unsupported"}
