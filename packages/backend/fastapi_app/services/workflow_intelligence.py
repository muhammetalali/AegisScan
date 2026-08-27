from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def enrich_action(action: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    created = parse_iso(action["createdAt"])
    due = created.timestamp() + int(action.get("slaHours", 24)) * 3600
    remaining = int(due - now.timestamp())
    if action.get("state") in {"verified", "rejected"}:
        sla_state = "closed"
    elif remaining < 0:
        sla_state = "breached"
    elif remaining <= 6 * 3600:
        sla_state = "at_risk"
    else:
        sla_state = "on_track"
    completion_states = {"verified"}
    return {
        **action,
        "sla": {
            "state": sla_state,
            "dueAt": datetime.fromtimestamp(due, timezone.utc).isoformat(),
            "remainingHours": round(remaining / 3600, 1),
        },
        "requiresApproval": action.get("priority", 0) >= 85 and action.get("state") == "pending",
        "completion": 100 if action.get("state") in completion_states else 0,
    }


def workflow_metrics(actions: list[dict[str, Any]]) -> dict[str, Any]:
    enriched = [enrich_action(action) for action in actions]
    return {
        "total": len(enriched),
        "critical": sum(1 for a in enriched if a.get("priority", 0) >= 85),
        "onTrack": sum(1 for a in enriched if a["sla"]["state"] == "on_track"),
        "atRisk": sum(1 for a in enriched if a["sla"]["state"] == "at_risk"),
        "breached": sum(1 for a in enriched if a["sla"]["state"] == "breached"),
        "awaitingApproval": sum(1 for a in enriched if a["requiresApproval"]),
        "verified": sum(1 for a in enriched if a.get("state") == "verified"),
    }
