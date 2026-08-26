from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

_ACTIONS: dict[str, dict[str, Any]] = {}

STATES = ["pending", "approved", "assigned", "in_progress", "awaiting_revalidation", "verified", "rejected", "deferred"]
TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "deferred"},
    "approved": {"assigned", "deferred"},
    "assigned": {"in_progress", "deferred"},
    "in_progress": {"awaiting_revalidation", "deferred"},
    "awaiting_revalidation": {"verified", "in_progress", "deferred"},
    "verified": set(),
    "rejected": set(),
    "deferred": {"pending", "approved"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_action(decision: dict[str, Any], owner: str, sla_hours: int, requested_by: str) -> dict[str, Any]:
    node_id = str(decision.get("nodeId") or "unknown")
    action_id = f"act-{node_id.replace(':', '-').replace('/', '-')}-{uuid4().hex[:6]}"
    now = _now()
    item = {
        "actionId": action_id,
        "decisionId": decision.get("decisionId"),
        "nodeId": node_id,
        "title": f"Remediate: {decision.get('label', 'Security finding')}",
        "owner": owner,
        "requestedBy": requested_by,
        "slaHours": max(1, sla_hours),
        "state": "pending",
        "riskBefore": int(decision.get("risk", 0) or 0),
        "confidenceBefore": int(decision.get("confidence", 0) or 0),
        "priority": int(decision.get("priority", 0) or 0),
        "recommendedAction": decision.get("recommendedAction", "Apply remediation and re-validate."),
        "remediationPlan": decision.get("revalidationPlan", []),
        "createdAt": now,
        "updatedAt": now,
        "events": [{"type": "action.created", "at": now, "actor": requested_by}],
    }
    _ACTIONS[action_id] = item
    return item


def transition(action_id: str, state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    if action_id not in _ACTIONS:
        raise KeyError(action_id)
    if state not in STATES:
        raise ValueError(state)
    item = _ACTIONS[action_id]
    current = item["state"]
    if state not in TRANSITIONS.get(current, set()):
        raise ValueError(f"Invalid transition: {current} -> {state}")
    item["state"] = state
    item["updatedAt"] = _now()
    item["events"].append({"type": f"action.{state}", "at": item["updatedAt"], "actor": actor, "note": note})
    return item


def list_actions() -> list[dict[str, Any]]:
    return sorted(_ACTIONS.values(), key=lambda x: x["updatedAt"], reverse=True)


def get_action(action_id: str) -> dict[str, Any] | None:
    return _ACTIONS.get(action_id)
