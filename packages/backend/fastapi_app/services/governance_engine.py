from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

POLICY_TIERS = {
    "critical": {"approval": "ciso", "escalation": ["security_manager", "ciso"], "sla_hours": 4},
    "high": {"approval": "security_manager", "escalation": ["security_manager"], "sla_hours": 24},
    "medium": {"approval": "analyst", "escalation": ["security_manager"], "sla_hours": 72},
    "low": {"approval": "none", "escalation": ["analyst"], "sla_hours": 168},
}


def evaluate_governance(action: dict[str, Any]) -> dict[str, Any]:
    priority = int(action.get("priority", 0) or 0)
    risk = int(action.get("riskBefore", 0) or 0)
    tier = "critical" if risk >= 90 or priority >= 85 else "high" if risk >= 75 or priority >= 70 else "medium" if risk >= 45 else "low"
    policy = POLICY_TIERS[tier]
    sla_state = (action.get("sla") or {}).get("state", "unknown")
    approval_required = policy["approval"] != "none"
    escalation_level = 0
    if sla_state == "at_risk":
        escalation_level = 1
    elif sla_state == "breached":
        escalation_level = 2
    if tier == "critical" and sla_state == "breached":
        escalation_level = 3
    return {
        "policyTier": tier,
        "approvalRequired": approval_required,
        "approvalRole": policy["approval"],
        "escalationTargets": policy["escalation"],
        "escalationLevel": escalation_level,
        "policySlaHours": policy["sla_hours"],
        "governanceState": "escalated" if escalation_level else "approval_required" if approval_required and action.get("state") == "pending" else "controlled",
        "rationale": f"Tier {tier} policy selected from risk={risk} and priority={priority}. SLA={sla_state}; approval={policy['approval']}.",
        "evaluatedAt": datetime.now(timezone.utc).isoformat(),
    }


def enrich_governance(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**action, "governance": evaluate_governance(action)} for action in actions]


def governance_metrics(actions: list[dict[str, Any]]) -> dict[str, int]:
    enriched = enrich_governance(actions)
    return {
        "total": len(enriched),
        "approvalRequired": sum(bool(a["governance"]["approvalRequired"]) for a in enriched),
        "escalated": sum(a["governance"]["escalationLevel"] > 0 for a in enriched),
        "criticalPolicy": sum(a["governance"]["policyTier"] == "critical" for a in enriched),
        "breached": sum((a.get("sla") or {}).get("state") == "breached" for a in enriched),
    }
